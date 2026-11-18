"""Who may read a resource's data: files, DataStore rows and derived outputs.

Metadata stays public. Reading data needs a signed-in user, and for a
restricted dataset one who is a sysadmin, on an allowed email domain, a
member of the owning organisation or a dataset collaborator. Private datasets
are left to CKAN's own checks, which run alongside this one.
"""

import hashlib
import json
import logging
import os
import re

from flask import Blueprint, Response, has_request_context

import ckan.model as model
import ckan.plugins.toolkit as tk

log = logging.getLogger(__name__)

# Every route that serves a resource's bytes: core, s3filestore and
# googleanalytics downloads, derived formats, the resource proxy and DataStore
# dumps. The dump view would otherwise fail mid-stream with a 500.
DATA_PATH = re.compile(
    r"^(?:/[a-z]{2}(?:_[A-Z]{2})?)?(?:"
    r"/dataset/[^/]+/resource/([^/]+)/(?:fs_download|download|derived|proxy)(?:/|$)"
    r"|/datastore/dump/([^/]+)$)"
)


def data_path_resource(path):
    """The resource id a data route serves, or ``None``."""
    match = DATA_PATH.match(path or "")
    return (match.group(1) or match.group(2)) if match else None

ALLOWED_DOMAINS_ENV = "CKANEXT__SSE__REQUEST_ACCESS_ALLOWED_EMAIL_DOMAINS"

# Organisations approved by SSE for restricted data, as a JSON object mapping
# each organisation's name to its email domains. Changed through SSE change
# management; unset or invalid means no outside organisation is approved.
APPROVED_ORGANISATIONS_ENV = "CKANEXT__SSE__APPROVED_ORGANISATIONS"

NOT_APPROVED_MESSAGE = (
    "Restricted data can only be shared with users from organisations approved "
    "by SSEN. Your email address does not belong to an approved organisation."
)
NOT_APPROVED_GRANT_MESSAGE = (
    "This user is not from an organisation approved by SSEN, so they cannot be "
    "given access to restricted data."
)


def allowed_email_domains():
    """Internal domains whose users read every restricted dataset."""
    raw = os.environ.get(ALLOWED_DOMAINS_ENV, "")
    return [d.strip().lower() for d in raw.split(",") if d.strip()]


def approved_organisations():
    """``{organisation name: [domains]}`` from the environment."""
    raw = os.environ.get(APPROVED_ORGANISATIONS_ENV, "").strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        return {
            str(name).strip(): sorted({str(d).strip().lower().lstrip("@") for d in domains if str(d).strip()})
            for name, domains in parsed.items()
            if str(name).strip()
        }
    except Exception:
        log.error("%s is not a JSON object of organisation -> domains; "
                  "no organisation is approved", APPROVED_ORGANISATIONS_ENV)
        return {}


def log_approved_organisations():
    """Record the allowlist in the audit log each time CKAN starts, so every
    change shipped through a deployment leaves a dated record."""
    from ckanext.sse.audit import emit_audit_log

    orgs = approved_organisations()
    emit_audit_log(
        action="approved_organisations_loaded",
        status="success",
        message="{} approved organisation(s) for restricted data".format(len(orgs)),
        organisations=orgs,
        internal_domains=allowed_email_domains(),
        fingerprint=hashlib.sha256(json.dumps(orgs, sort_keys=True).encode()).hexdigest()[:16],
    )


def _email_domain(email):
    email = (email or "").strip().lower()
    return email.rsplit("@", 1)[1] if "@" in email else ""


def approved_organisation(email):
    """The approved organisation an email address belongs to, or ``None``.

    Internal domains count as approved. Domains match exactly, so a
    subdomain or a look-alike domain is not approved.
    """
    domain = _email_domain(email)
    if not domain:
        return None
    if domain in allowed_email_domains():
        return "SSEN"
    for name, domains in approved_organisations().items():
        if domain in domains:
            return name
    return None


def is_restricted(package):
    """``package`` is a ``model.Package`` or a package dict."""
    if isinstance(package, dict):
        value = package.get("is_restricted")
        if value is None:
            value = next((e.get("value") for e in package.get("extras") or []
                          if e.get("key") == "is_restricted"), None)
    else:
        value = package.extras.get("is_restricted")
    return tk.asbool(value) if value is not None else False


def _is_anonymous(user_obj):
    return user_obj is None or getattr(user_obj, "is_anonymous", False)


def _has_allowed_domain(user_obj):
    return _email_domain(user_obj.email) in allowed_email_domains()


def _is_org_member(user_obj, package_id, owner_org):
    if not owner_org:
        return False
    return (
        model.Session.query(model.Member)
        .filter(model.Member.group_id == owner_org)
        .filter(model.Member.table_name == "user")
        .filter(model.Member.table_id == user_obj.id)
        .filter(model.Member.state == "active")
        .count()
        > 0
    )


def _is_collaborator(user_obj, package_id):
    return (
        model.Session.query(model.PackageMember)
        .filter(model.PackageMember.package_id == package_id)
        .filter(model.PackageMember.user_id == user_obj.id)
        .count()
        > 0
    )


def has_restricted_access(user_obj, package_id, owner_org):
    """Whether a signed-in user may read a restricted dataset's data."""
    if _is_anonymous(user_obj):
        return False
    return (
        user_obj.sysadmin
        or _has_allowed_domain(user_obj)
        or _is_org_member(user_obj, package_id, owner_org)
        or (_is_collaborator(user_obj, package_id)
            and approved_organisation(user_obj.email) is not None)
    )


def refusal(user_obj, package):
    """Why ``user_obj`` may not read ``package``'s data, or ``None`` if they may."""
    if _is_anonymous(user_obj):
        return tk._("You must be signed in to access this data.")
    if is_restricted(package) and not has_restricted_access(
        user_obj, package.id, package.owner_org
    ):
        return tk._("You do not have access to this restricted data.")
    return None


def context_user(context):
    """The user an action runs as. ``auth_user_obj`` is flask-login's
    ``AnonymousUser`` on API calls, so fall back to the ``user`` name."""
    user_obj = context.get("auth_user_obj")
    if not _is_anonymous(user_obj):
        return user_obj
    name = context.get("user")
    return model.User.get(name) if name else None


def resource_package(resource_id):
    resource = model.Resource.get(resource_id) if resource_id else None
    if resource is None or resource.state != "active":
        return None
    return resource.package


def auth_result(context, resource_ids):
    """Auth function result for reading the data of ``resource_ids``."""
    user_obj = context_user(context)
    if _is_anonymous(user_obj):
        return {"success": False, "msg": refusal(None, None)}
    for resource_id in resource_ids:
        package = resource_package(resource_id)
        if package is None:
            continue
        reason = refusal(user_obj, package)
        if reason:
            return {"success": False, "msg": reason}
    return {"success": True}


def _schema_only(data_dict):
    """A search that returns column definitions and no rows or counts, as
    ``datastore_info`` makes through ``datastore_dictionary``."""
    return (
        str(data_dict.get("limit")) == "0"
        and not tk.asbool(data_dict.get("include_total", True))
        and not data_dict.get("q")
        and not data_dict.get("filters")
    )


@tk.chained_auth_function
def datastore_search(next_auth, context, data_dict):
    result = next_auth(context, data_dict)
    if not result.get("success") or _schema_only(data_dict):
        return result
    return auth_result(context, [data_dict.get("resource_id") or data_dict.get("id")])


datastore_search.auth_allow_anonymous_access = True


@tk.chained_auth_function
def datastore_search_sql(next_auth, context, data_dict):
    result = next_auth(context, data_dict)
    if not result.get("success"):
        return result
    return auth_result(context, context.get("table_names") or [])


def _current_user():
    try:
        from ckan.common import current_user

        return current_user
    except Exception:
        return None


def enforce_data_routes():
    """Refuse a request for a resource's bytes the caller may not read."""
    if not has_request_context():
        return None
    resource_id = data_path_resource(tk.request.path)
    if not resource_id:
        return None
    package = resource_package(resource_id)
    if package is None:
        return None
    user_obj = _current_user()
    if user_obj is not None and not _is_anonymous(user_obj):
        user_obj = model.User.get(user_obj.id)
    reason = refusal(user_obj, package)
    if reason:
        log.info("Data access refused on %s: %s", tk.request.path, reason)
        return Response(reason, status=403, mimetype="text/plain")
    return None


blueprint = Blueprint("sse_data_access", __name__)
blueprint.before_app_request(enforce_data_routes)
