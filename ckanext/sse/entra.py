"""Entra ID account linkage, identity lock, and deactivation sweep.

Users who sign in through Microsoft Entra (Azure AD) are governed by SSE's own
directory. Consequences for CKAN:

* their identity fields (email, password) must not be settable in CKAN -- a
  local password would bypass Entra's controls (MFA, conditional access, and
  the disablement the SCIM endpoint enforces), and a local email change would
  break the mapping back to the directory;

* they are matched to the directory on the immutable Entra **object id**, not
  the mutable email. The oauth2 SSO extension stamps that id onto the user's
  ``plugin_extras`` under the ``ssen`` namespace on every login; and

* when the directory disables a user, CKAN must disable every matching account
  -- matched by object id *and* by case-insensitive email, since CKAN emails
  are case-insensitive and a person may hold more than one account.

The ``ssen`` plugin_extras namespace is shared with the dormancy lifecycle
(``account_lifecycle``): ``entra_oid``, ``disabled_reason``, ``disabled_at``.
"""

import datetime
import logging

from sqlalchemy import func

import ckan.model as model
from ckan.model import State

log = logging.getLogger(__name__)

NAMESPACE = "ssen"
OID_KEY = "entra_oid"
DISABLED_REASON = "entra_disabled"


# --------------------------------------------------------------------------
# Linkage
# --------------------------------------------------------------------------

def entra_oid(user_obj):
    """The Entra object id linked to this user, or ``None``."""
    if user_obj is None:
        return None
    extras = user_obj.plugin_extras or {}
    return (extras.get(NAMESPACE) or {}).get(OID_KEY)


def is_sso_user(user_obj):
    """Whether this account is governed by Entra SSO (has a linked object id)."""
    return entra_oid(user_obj) is not None


def users_by_entra_oid(oid):
    """Every CKAN user carrying this Entra object id. There should be exactly
    one, but a disable sweep must not miss a duplicate, so all rows are
    returned.
    """
    if not oid:
        return []
    return (
        model.Session.query(model.User)
        .filter(model.User.plugin_extras[NAMESPACE][OID_KEY].astext == oid)
        .all()
    )


def user_by_entra_oid(oid):
    """The CKAN user carrying this Entra object id, or ``None``."""
    users = users_by_entra_oid(oid)
    return users[0] if users else None


# --------------------------------------------------------------------------
# Deactivation sweep (AC-2.13 / AC-2.3)
# --------------------------------------------------------------------------

def matching_users(oid, email=None):
    """Every CKAN account for this directory user: the one linked by object id,
    plus any whose email matches case-insensitively (duplicates, or accounts
    that predate the object-id link). De-duplicated.
    """
    found = {}
    for linked in users_by_entra_oid(oid):
        found[linked.id] = linked
    if email:
        rows = (
            model.Session.query(model.User)
            .filter(func.lower(model.User.email) == email.strip().lower())
            .all()
        )
        for u in rows:
            # Only sweep an email match that is not firmly bound to a *different*
            # Entra identity -- otherwise a shared/case-variant email could pull
            # in someone else's account.
            other = entra_oid(u)
            if other is None or other == oid:
                found[u.id] = u
    return list(found.values())


def deactivate(oid, email=None, reason=DISABLED_REASON):
    """Disable every matching account and revoke its tokens. Returns them."""
    users = matching_users(oid, email)
    for user in users:
        _disable(user, reason)
    if users:
        model.Session.commit()
    return users


def reactivate(oid, email=None):
    """Re-enable every matching account (directory is the source of truth)."""
    users = matching_users(oid, email)
    for user in users:
        user.state = State.ACTIVE
        user.last_active = datetime.datetime.utcnow()
        extras = dict(user.plugin_extras or {})
        ns = dict(extras.get(NAMESPACE) or {})
        for key in ("disabled_reason", "disabled_at"):
            ns.pop(key, None)
        extras[NAMESPACE] = ns
        user.plugin_extras = extras
        model.Session.add(user)
    if users:
        model.Session.commit()
    return users


def _disable(user, reason):
    user.state = State.DELETED
    extras = dict(user.plugin_extras or {})
    ns = dict(extras.get(NAMESPACE) or {})
    ns["disabled_reason"] = reason
    ns["disabled_at"] = datetime.datetime.utcnow().isoformat()
    extras[NAMESPACE] = ns
    user.plugin_extras = extras
    model.Session.add(user)
    _revoke_tokens(user)
    log.info("Entra deactivation: disabled user %s (%s)", user.name, reason)


def _revoke_tokens(user):
    """Delete the user's API tokens so live sessions (incl. the portal's
    frontend_token) die immediately rather than lasting until they expire.
    """
    for token in (
        model.Session.query(model.ApiToken)
        .filter(model.ApiToken.user_id == user.id)
        .all()
    ):
        model.Session.delete(token)
