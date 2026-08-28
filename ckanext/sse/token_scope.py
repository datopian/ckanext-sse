"""Least-privilege scoping for API tokens, by token name (#325, #331).

A CKAN API token inherits the full rights of the user it belongs to -- there is
no native per-token scope. So a leaked ``frontend_token`` belonging to an
organisation editor or a sysadmin can create datasets, edit users, anything the
user can. This module constrains named tokens to only the actions they are
meant to perform, and default-denies the rest.

The scope is keyed off the token *name*:

* ``frontend_token`` -- the token the decoupled frontend holds for a signed-in
  user. Allowed only the actions the frontend actually calls (audited); every
  write/admin action is denied.
* ``smart_meter_token`` -- the token a verified user uses against the documented
  Smart Meter API. That endpoint only calls ``user_extras`` on CKAN (to check
  ``is_verified_user``); the data itself is served from BigQuery. So this token
  needs ``user_extras`` and nothing else -- which is what keeps a non-expiring
  token safe.

Any other token name (a user's personal token) is left alone: it keeps the full
rights it has today.

How the token is identified
---------------------------

Enforced from a ``before_app_request`` handler, the same mechanism the session
and password policies use. CKAN's ``_get_user_for_apitoken`` reads the token
from the header and throws the token object away, so the name is recovered the
same way core resolves the user: ``api_token.decode`` -> ``jti`` ->
``ApiToken.get(jti).name``.

Enforcement point is the action API. The frontend reaches CKAN only through
``/api/.../action/<name>`` (including ``datastore_search_sql``), so the handler
reads the action name from the request *path* and checks it against the
allowlist. (The path, not ``request.endpoint`` / ``view_args``: those are not
reliably populated by the time a ``before_app_request`` handler runs here.) A
scoped token presented on any other path is denied too -- these tokens have no
business anywhere but their allowlisted actions.

Failure handling: an error *identifying* the token leaves the request alone
(the token may not be ours, and a decode bug must not take the site down). Once
a token is known to be scoped, anything we cannot positively allow is denied --
an authorisation control fails closed.
"""

import datetime
import json
import logging
import os
import re

from flask import Blueprint, Response, has_request_context

import ckan.lib.api_token as api_token
import ckan.model as model
import ckan.plugins.toolkit as toolkit

log = logging.getLogger(__name__)

_ = toolkit._

# Actions the decoupled frontend calls with the user's token. Every read the
# portal performs plus the handful of writes the UI triggers; nothing that
# creates, edits or deletes datasets, resources, users or organisations, and
# nothing that mints a general-purpose token. Derived from the actual CKAN calls
# in ssen-portal (grep of ``action/<name>`` + ``CkanRequest``) -- a name the
# frontend calls with the token but that is missing here is default-denied and
# breaks that page, so this has to stay in step with the frontend.
FRONTEND_TOKEN_ACTIONS = frozenset(
    {
        # -- writes the UI performs --
        "data_reuse_create",
        "follow_dataset",
        "unfollow_dataset",
        "follow_group",
        "unfollow_group",
        "request_access_to_dataset",
        # regenerate the user's own Smart Meter token (mints a *less*
        # privileged token; safe for the frontend to trigger)
        "smart_meter_token_create",
        # -- package / resource reads --
        "package_show",
        "package_list",
        "package_search",
        "package_activity_list",
        "current_package_list_with_resources",
        "resource_show",
        "resource_activity_list",
        # -- datastore reads (data explorer, map & viz builders) --
        "datastore_search",
        "datastore_search_sql",
        "datastore_info",
        # -- group / organisation reads --
        "group_show",
        "group_list",
        "group_activity_list",
        "group_followee_list",
        "organization_show",
        "organization_list",
        "organization_activity_list",
        # -- user / misc reads --
        "user_extras",
        "user_show",
        "dataset_followee_list",
        "license_list",
        "tag_list",
        "data_reuse_list",
        "data_reuse_show",
        # -- showcase reads --
        "ckanext_showcase_list",
        "ckanext_showcase_show",
        "ckanext_showcase_package_list",
        "ckanext_package_showcase_list",
    }
)

# The Smart Meter token proves "who am I / am I verified" and nothing else; the
# data is BigQuery, not CKAN.
SMART_METER_TOKEN_ACTIONS = frozenset({"user_extras"})

# Token name -> the only actions that name may call. A name absent here is an
# ordinary token and keeps its full rights.
ALLOWLISTS = {
    "frontend_token": FRONTEND_TOKEN_ACTIONS,
    "smart_meter_token": SMART_METER_TOKEN_ACTIONS,
}

# The name of the decoupled frontend's per-user token. Only this name is given a
# hard expiry below.
FRONTEND_TOKEN_NAME = "frontend_token"


def _frontend_token_ttl_seconds():
    """Hard lifetime for the frontend token, in seconds (0 disables it).

    Kept just above the frontend's own rotation window
    (``SESSION_TOKEN_ROTATION_MINUTES``, default 30) so a live session always
    re-mints before this bites -- while a token that stops being rotated,
    because the session went idle or the token leaked, dies on its own instead
    of living forever. The frontend token is a CKAN JWT with no native expiry
    otherwise; this is what makes it genuinely short-lived.
    """
    return toolkit.asint(
        os.environ.get("CKANEXT__SSE__FRONTEND_TOKEN_TTL_MINUTES", 35)) * 60


def set_token_expiry(data, jti, data_dict):
    """Stamp an ``exp`` claim on the frontend token, and only that token.

    An ``IApiToken.postprocess_api_token`` hook: it runs while a token is being
    minted, keyed on the token *name* exactly like the scope allowlist. So the
    smart_meter_token and users' personal tokens are left untouched and keep
    CKAN's default non-expiring behaviour -- only ``frontend_token`` is bounded.
    PyJWT enforces ``exp`` on decode, so an expired frontend token simply stops
    authenticating.
    """
    if data_dict.get("name") != FRONTEND_TOKEN_NAME:
        return data
    ttl = _frontend_token_ttl_seconds()
    if ttl > 0:
        expire_at = datetime.datetime.utcnow() + datetime.timedelta(seconds=ttl)
        data["exp"] = api_token.into_seconds(expire_at)
    return data


def _presented_token():
    """The raw API token on this request, or ``None``.

    Mirrors core ``_get_user_for_apitoken``: the configured header, then the
    ``Authorization`` header. A value with a space is HTTP auth, not an API
    token (CKAN tokens carry none), so it is ignored -- which also means a
    ``Bearer <token>`` prefix is not our concern, matching core.
    """
    header_name = toolkit.config.get("apikey_header_name", "Authorization")
    raw = (toolkit.request.headers.get(header_name)
           or toolkit.request.headers.get("Authorization")
           or "")
    raw = raw.strip()
    if not raw or " " in raw:
        return None
    return raw


def _token_name(raw):
    """The name of the token behind ``raw``, or ``None`` if it is not a token."""
    data = api_token.decode(raw)
    if not data or "jti" not in data:
        return None
    token_obj = model.ApiToken.get(data["jti"])
    return token_obj.name if token_obj is not None else None


# ``/api/action/<name>`` and ``/api/<ver>/action/<name>``, with an optional
# locale prefix. Parsed from the path rather than read from
# ``request.endpoint`` / ``view_args``: those are not reliably populated by the
# time a ``before_app_request`` handler runs in this stack, whereas the path
# always is.
_ACTION_PATH = re.compile(r"/api(?:/\d+)?/action/([^/?]+)")


def _current_action():
    """The action being called, if this is an action-API request."""
    match = _ACTION_PATH.search(toolkit.request.path or "")
    return match.group(1) if match else None


def enforce_token_scope():
    """Refuse a scoped token any action outside its allowlist.

    Returns ``None`` to let the request through. Runs before every view, so an
    error in identifying the token must not raise.
    """
    if not has_request_context():
        return None

    raw = _presented_token()
    if not raw:
        return None

    try:
        name = _token_name(raw)
    except Exception:
        # Could not identify the token -- it may not even be ours. Leaving the
        # request alone is safe: a real scoped token still decodes fine, and a
        # decode bug must not lock the whole site out.
        log.exception("Token scope: could not identify token; allowing request")
        return None

    allowed = ALLOWLISTS.get(name)
    if allowed is None:
        # No token, or an ordinary full-rights token. Not our business.
        return None

    # From here the request carries a scoped token: default-deny.
    action = _current_action()
    if action is not None and action in allowed:
        return None

    log.warning(
        "Token scope: %s blocked from %s",
        name, action or (toolkit.request.endpoint or toolkit.request.path),
    )
    return _forbidden()


def _forbidden():
    """A 403 in CKAN's action-API error shape, so clients can parse it.

    Returned rather than raised to match the other ``before_app_request``
    handlers in this extension, which short-circuit by returning a response.
    """
    body = {
        "success": False,
        "error": {
            "__type": "Authorization Error",
            "message": _("This token is not permitted to perform that "
                         "action."),
        },
    }
    return Response(json.dumps(body), status=403,
                    mimetype="application/json")


# Routeless: it exists only to hang the scope check off ``before_app_request``.
blueprint = Blueprint("sse_token_scope", __name__)


@blueprint.before_app_request
def _before_app_request():
    return enforce_token_scope()
