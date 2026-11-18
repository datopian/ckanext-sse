"""Who may read a resource's data: files, DataStore rows and derived outputs.

Metadata stays public. Reading data needs a signed-in user, and for a
restricted dataset one who is a sysadmin, on an allowed email domain, a
member of the owning organisation or a dataset collaborator. Private datasets
are left to CKAN's own checks, which run alongside this one.
"""

import logging
import os
import re

from flask import Blueprint, Response, has_request_context

import ckan.model as model
import ckan.plugins.toolkit as tk

log = logging.getLogger(__name__)

# Every route that serves a resource's bytes: core, s3filestore and
# googleanalytics downloads, derived formats and the resource proxy.
DATA_PATH = re.compile(
    r"^(?:/[a-z]{2}(?:_[A-Z]{2})?)?/dataset/[^/]+/resource/([^/]+)/"
    r"(?:fs_download|download|derived|proxy)(?:/|$)"
)

ALLOWED_DOMAINS_ENV = "CKANEXT__SSE__REQUEST_ACCESS_ALLOWED_EMAIL_DOMAINS"


def allowed_email_domains():
    raw = os.environ.get(ALLOWED_DOMAINS_ENV, "")
    return [d.strip().lower() for d in raw.split(",") if d.strip()]


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
    email = (user_obj.email or "").lower()
    return any(email.endswith("@" + d) for d in allowed_email_domains())


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
        or _is_collaborator(user_obj, package_id)
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


@tk.chained_auth_function
def datastore_search(next_auth, context, data_dict):
    result = next_auth(context, data_dict)
    if not result.get("success"):
        return result
    return auth_result(context, [data_dict.get("resource_id") or data_dict.get("id")])


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
    match = DATA_PATH.match(tk.request.path or "")
    if not match:
        return None
    package = resource_package(match.group(1))
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
