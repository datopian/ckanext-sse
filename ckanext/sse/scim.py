"""SCIM 2.0 endpoint for Entra ID user provisioning (deactivation sync).

Microsoft Entra is configured as the SCIM *client*: it authenticates to this
endpoint with a bearer token that SSE holds, and pushes user lifecycle changes
to us. We never hold any Entra credential -- the credential direction is
reversed from an outbound Graph poll, which is why this is the approach the
client asked for.

The behaviour we care about is deactivation: when Entra disables (or
deprovisions) a user, it sends ``active: false`` (PATCH/PUT) or DELETE, and we
disable every matching CKAN account -- see ``entra.deactivate``. Provisioning
(POST) never creates a CKAN account: accounts come into being on SSO login.
It only links an existing account and stamps its Entra object id, so later
updates match on the immutable id rather than the mutable email. A POST for a
user with no CKAN account is acknowledged but writes nothing.

Only the subset Entra exercises is implemented; it is enough to drive the
enterprise-application provisioning job end to end.
"""

import json
import logging
import re

from flask import Blueprint, request, jsonify, make_response

import ckan.model as model
import ckan.plugins.toolkit as toolkit
from ckan.model import State

from ckanext.sse import entra

log = logging.getLogger(__name__)

blueprint = Blueprint("sse_scim", __name__, url_prefix="/scim/v2")

USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
ERROR_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:Error"


# --------------------------------------------------------------------------
# Auth
# --------------------------------------------------------------------------

def _configured_token():
    return toolkit.config.get("ckanext.sse.scim.token")


def _authorised():
    token = _configured_token()
    if not token:
        return False
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return False
    import secrets
    return secrets.compare_digest(header[7:], token)


def _scim_error(status, detail):
    resp = make_response(
        json.dumps({"schemas": [ERROR_SCHEMA], "detail": detail, "status": str(status)}),
        status,
    )
    resp.headers["Content-Type"] = "application/scim+json"
    return resp


@blueprint.before_request
def _guard():
    # ServiceProviderConfig et al. are also protected; Entra sends the token.
    if _configured_token() is None:
        return _scim_error(404, "SCIM not configured")
    if not _authorised():
        return _scim_error(401, "Unauthorized")


@blueprint.after_request
def _scim_content_type(resp):
    # Entra's SCIM client expects application/scim+json, not application/json.
    if resp.mimetype == "application/json":
        resp.headers["Content-Type"] = "application/scim+json"
    return resp


# --------------------------------------------------------------------------
# Mapping
# --------------------------------------------------------------------------

def _user_to_scim(user):
    return {
        "schemas": [USER_SCHEMA],
        "id": user.id,
        "externalId": entra.entra_oid(user),
        "userName": user.email or user.name,
        "active": user.state == State.ACTIVE,
        "name": {"formatted": user.fullname or user.name},
        "emails": [{"value": user.email, "primary": True}] if user.email else [],
        "meta": {"resourceType": "User"},
    }


def _scim_list(users):
    return jsonify({
        "schemas": [LIST_SCHEMA],
        "totalResults": len(users),
        "startIndex": 1,
        "itemsPerPage": len(users),
        "Resources": [_user_to_scim(u) for u in users],
    })


# --------------------------------------------------------------------------
# Discovery documents (probed by Entra during setup)
# --------------------------------------------------------------------------

@blueprint.route("/ServiceProviderConfig")
def service_provider_config():
    return jsonify({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "patch": {"supported": True},
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": 200},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": False},
        "authenticationSchemes": [{
            "type": "oauthbearertoken",
            "name": "OAuth Bearer Token",
            "description": "Authentication via the SCIM bearer token.",
        }],
    })


@blueprint.route("/ResourceTypes")
def resource_types():
    return jsonify({
        "schemas": [LIST_SCHEMA],
        "totalResults": 1,
        "Resources": [{
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": "User",
            "name": "User",
            "endpoint": "/Users",
            "schema": USER_SCHEMA,
        }],
    })


@blueprint.route("/Schemas")
def schemas():
    return jsonify({"schemas": [LIST_SCHEMA], "totalResults": 0, "Resources": []})


# --------------------------------------------------------------------------
# Users
# --------------------------------------------------------------------------

_FILTER_RE = re.compile(r'(\w+)\s+eq\s+"([^"]+)"', re.IGNORECASE)


@blueprint.route("/Users", methods=["GET"])
def list_users():
    """Entra looks a user up before creating/updating, filtering on userName or
    externalId. We only need to answer those two.
    """
    flt = request.args.get("filter", "")
    match = _FILTER_RE.search(flt or "")
    if not match:
        return _scim_list([])
    attr, value = match.group(1).lower(), match.group(2)
    user = None
    if attr == "externalid":
        user = entra.user_by_entra_oid(value)
    elif attr in ("username", "emails.value"):
        from sqlalchemy import func
        user = (
            model.Session.query(model.User)
            .filter(func.lower(model.User.email) == value.strip().lower())
            .first()
        )
    return _scim_list([user] if user else [])


@blueprint.route("/Users/<user_id>", methods=["GET"])
def get_user(user_id):
    user = model.User.get(user_id)
    if user is None:
        return _scim_error(404, "User not found")
    return jsonify(_user_to_scim(user))


@blueprint.route("/Users", methods=["POST"])
def create_user():
    """Provision: link an existing CKAN account and stamp its object id.

    Never creates a CKAN account -- accounts are created on SSO login. A user
    with no matching CKAN account is acknowledged with a stub response (so
    Entra records success rather than erroring) but nothing is written; a
    disable in the same request is still applied, which is a no-op when there
    is no account.
    """
    body = request.get_json(force=True, silent=True) or {}
    oid = body.get("externalId")
    email = _primary_email(body)
    active = body.get("active", True)

    users = entra.matching_users(oid, email) if (oid or email) else []
    user = users[0] if users else None

    if user is None:
        if active is False:
            entra.deactivate(oid, email)
        return _scim_stub_response(oid, email, active)

    _stamp_oid(user, oid)
    if active is False:
        entra.deactivate(oid, email)
        user = model.User.get(user.id)
    else:
        model.Session.commit()

    resp = make_response(jsonify(_user_to_scim(user)))
    resp.status_code = 201
    return resp


@blueprint.route("/Users/<user_id>", methods=["PUT"])
def replace_user(user_id):
    user = model.User.get(user_id)
    if user is None:
        return _scim_error(404, "User not found")
    body = request.get_json(force=True, silent=True) or {}
    oid = body.get("externalId") or entra.entra_oid(user)
    email = _primary_email(body) or user.email
    active = body.get("active", True)
    _apply_active(active, oid, email)
    return jsonify(_user_to_scim(model.User.get(user_id)))


@blueprint.route("/Users/<user_id>", methods=["PATCH"])
def patch_user(user_id):
    user = model.User.get(user_id)
    if user is None:
        return _scim_error(404, "User not found")
    body = request.get_json(force=True, silent=True) or {}
    active = _active_from_patch(body)
    if active is not None:
        oid = entra.entra_oid(user)
        _apply_active(active, oid, user.email)
    return jsonify(_user_to_scim(model.User.get(user_id)))


@blueprint.route("/Users/<user_id>", methods=["DELETE"])
def delete_user(user_id):
    """Deprovisioning is a disable, never a hard delete."""
    user = model.User.get(user_id)
    if user is None:
        return _scim_error(404, "User not found")
    entra.deactivate(entra.entra_oid(user), user.email)
    return make_response("", 204)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _primary_email(body):
    emails = body.get("emails") or []
    primary = [e.get("value") for e in emails if e.get("primary")]
    if primary:
        return primary[0]
    if emails:
        return emails[0].get("value")
    # Entra commonly sends the UPN as userName, which is an email-shaped value.
    username = body.get("userName")
    return username if username and "@" in username else None


def _active_from_patch(body):
    """Extract the target active state from a PatchOp, tolerating the shapes
    Entra emits: ``path='active'`` with a bool/string value, or a valueless
    replace carrying ``{'active': ...}``.
    """
    for op in body.get("Operations", []):
        if (op.get("op") or "").lower() not in ("replace", "add"):
            continue
        path = (op.get("path") or "").lower()
        value = op.get("value")
        if path == "active":
            return _as_bool(value)
        if path == "" and isinstance(value, dict) and "active" in value:
            return _as_bool(value["active"])
    return None


def _as_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() == "true"
    return bool(value)


def _apply_active(active, oid, email):
    if active is False:
        entra.deactivate(oid, email)
    else:
        entra.reactivate(oid, email)


def _stamp_oid(user, oid):
    existing = entra.entra_oid(user)
    if not oid or existing == oid:
        return
    if existing is not None:
        # The account is already bound to a different Entra identity; never
        # re-link it (that would let one identity take over another's account).
        log.warning(
            "SCIM: refusing to re-link user %s from oid %s to %s",
            user.name, existing, oid,
        )
        return
    extras = dict(user.plugin_extras or {})
    ns = dict(extras.get(entra.NAMESPACE) or {})
    ns[entra.OID_KEY] = oid
    extras[entra.NAMESPACE] = ns
    user.plugin_extras = extras
    model.Session.add(user)


def _scim_stub_response(oid, email, active):
    """Acknowledge a provision for a user with no CKAN account, without
    creating one. Returns a minimal SCIM user (id keyed on the object id) so
    Entra treats the operation as a success instead of an error.
    """
    body = {
        "schemas": [USER_SCHEMA],
        "id": oid or email,
        "externalId": oid,
        "userName": email,
        "active": active is not False,
        "emails": [{"value": email, "primary": True}] if email else [],
        "meta": {"resourceType": "User"},
    }
    resp = make_response(jsonify(body))
    resp.status_code = 201
    return resp
