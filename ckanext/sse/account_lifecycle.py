"""Disablement of dormant accounts (AC-2.3).

SSE's *Standard for Access Control* AC-2.3 requires accounts to be disabled
automatically once they are "eligible for disablement", which it defines as:

* last logon greater than 45 days ago;
* creation date greater than 30 days ago;
* not in any "Admin Disablement" AD group.

The second clause is what stops a newly issued account being disabled before
its holder has had a chance to use it, and the third is the exemption list for
accounts that are supposed to sit idle -- here
``ckanext.sse.inactivity.exempt_users``, plus the site user, which is what
CKAN's own internal calls authenticate as.

Who the sweep applies to
------------------------

Only accounts that carry some privilege: sysadmins, members, editors and
admins of an organisation, and -- because they can edit datasets too -- users
made collaborators on a dataset.

The control exists to shrink the set of standing privileged access paths. A
registered account with no organisation and no collaboration has read access
to public data, which is what the portal offers anonymously anyway, so
disabling it after 45 days would churn ordinary data consumers without
retiring any access. This portal's registered population is mostly exactly
that. Organisation *members* are in scope even though the capacity is
read-only, because membership carries access to that organisation's private
datasets, which anonymous visitors do not have.

Set ``ckanext.sse.inactivity.privileged_only`` to false to sweep every dormant
account regardless.

Sysadmins are in scope. If a sweep ever disables the last active sysadmin,
``ckan sysadmin add <name>`` from a shell restores one -- the recovery path is
outside the web session the sweep can affect.

"Last logon" is read from ``user.last_active``, which CKAN stamps on every
authenticated request rather than only at sign-in. That is the better reading
of the control's intent -- an account making daily API calls is plainly in use
-- and it is the only per-user timestamp CKAN keeps. Accounts that have never
been active fall back to their creation date, so an account created 60 days
ago and never used is eligible, which is the case the control most wants
caught.

"Disabled" means CKAN's ``deleted`` state: the account can no longer sign in,
and a sysadmin can restore it from the user edit form. Nothing is destroyed.

There is no scheduler in a CKAN extension, so the sweep is a command --
``ckan sse disable-inactive-users`` -- to be run from cron or a Kubernetes
CronJob. It is idempotent and has a ``--dry-run``.

Configuration
-------------

===================================================== ====================
``ckanext.sse.inactivity.idle_days``                  45
``ckanext.sse.inactivity.min_account_age_days``       30
``ckanext.sse.inactivity.privileged_only``            true
``ckanext.sse.inactivity.capacities``                 admin editor member
``ckanext.sse.inactivity.include_collaborators``      true
``ckanext.sse.inactivity.exempt_sysadmins``           false
``ckanext.sse.inactivity.exempt_users``               names, space separated
===================================================== ====================
"""

import datetime
import logging
import os
import re

from flask import Blueprint, has_request_context
from flask_login import logout_user

import ckan.lib.mailer as mailer
import ckan.model as core_model
import ckan.plugins.toolkit as toolkit
from ckan.model.meta import Session

from ckanext.sse.audit import emit_audit_log

_ = toolkit._

# Days before disablement to email a warning. Matched as a window rather than
# an exact day, so a missed sweep run still warns.
DORMANCY_WARN_DAYS = (7, 1)

log = logging.getLogger(__name__)

# AC-2.3 e: "Last Logon GREATER THAN 45 days".
DEFAULT_IDLE_DAYS = 45

# AC-2.3 e: "Creation Date GREATER THAN 30 days".
DEFAULT_MIN_ACCOUNT_AGE_DAYS = 30


def _int_config(key, default):
    raw = toolkit.config.get(key, default)
    try:
        return max(0, toolkit.asint(raw))
    except (ValueError, TypeError):
        log.warning("Ignoring invalid %s %r, using %s", key, raw, default)
        return default


def idle_days():
    return _int_config("ckanext.sse.inactivity.idle_days", DEFAULT_IDLE_DAYS)


def min_account_age_days():
    return _int_config("ckanext.sse.inactivity.min_account_age_days",
                       DEFAULT_MIN_ACCOUNT_AGE_DAYS)


def exempt_users():
    """Accounts the sweep must never touch.

    The site user is in here unconditionally. It is what CKAN's own internal
    calls authenticate as, it never signs in, and disabling it breaks the
    site rather than securing it.
    """
    configured = toolkit.config.get("ckanext.sse.inactivity.exempt_users", "")
    names = {
        name.lower()
        for name in re.split(r"[,\s]+", (configured or "").strip())
        if name
    }
    site_user = toolkit.config.get("ckan.site_id", "")
    if site_user:
        names.add(site_user.lower())
    return names


def exempt_sysadmins():
    """Whether to leave sysadmins alone.

    False by default: a sysadmin account is the most valuable one on the site,
    so an idle one is exactly what the control is for. Where it has to be
    turned on -- an emergency account that is supposed to sit unused -- prefer
    naming it in ``exempt_users``, which is narrower.
    """
    return toolkit.asbool(
        toolkit.config.get("ckanext.sse.inactivity.exempt_sysadmins", False)
    )


def privileged_only():
    """Whether the sweep is limited to accounts that carry privilege."""
    return toolkit.asbool(
        toolkit.config.get("ckanext.sse.inactivity.privileged_only", True)
    )


def include_collaborators():
    """Whether a dataset collaboration counts as privilege.

    It does by default. A collaborator with the editor capacity can change
    datasets without belonging to any organisation, so leaving them out would
    exempt the very access the control is meant to retire.
    """
    return toolkit.asbool(
        toolkit.config.get("ckanext.sse.inactivity.include_collaborators",
                           True)
    )


def capacities():
    """Membership capacities that put an account in scope.

    All three by default. ``member`` is read-only within the organisation, but
    it still carries access to that organisation's private datasets, which is
    access an anonymous visitor does not have.
    """
    configured = toolkit.config.get("ckanext.sse.inactivity.capacities",
                                    "admin editor member")
    return {
        capacity.lower()
        for capacity in re.split(r"[,\s]+", (configured or "").strip())
        if capacity
    }


def privileged_user_ids():
    """Every user id holding an organisation membership or collaboration.

    One query per relationship rather than one per user: the sweep looks at
    every account on the site, and asking the database about each in turn
    would be a query per user for no benefit.
    """
    wanted = capacities()

    members = (
        Session.query(core_model.Member.table_id)
        .join(core_model.Group,
              core_model.Member.group_id == core_model.Group.id)
        .filter(
            core_model.Member.table_name == "user",
            core_model.Member.state == core_model.State.ACTIVE,
            core_model.Member.capacity.in_(wanted),
            # Organisations only. This portal also uses ``user_group`` groups,
            # membership of which grants read access to datasets shared with
            # the group and no write access at all.
            core_model.Group.is_organization.is_(True),
            core_model.Group.state == core_model.State.ACTIVE,
        )
        .all()
    )
    ids = {row.table_id for row in members}

    if include_collaborators():
        collaborators = (
            Session.query(core_model.PackageMember.user_id)
            .filter(core_model.PackageMember.capacity.in_(wanted))
            .all()
        )
        ids |= {row.user_id for row in collaborators}
    return ids


def last_activity(user):
    """When this account was last used, falling back to its creation."""
    return user.last_active or user.created


def is_privileged(user, privileged_ids=None):
    """Whether this account carries privilege worth retiring.

    ``privileged_ids`` is the precomputed set from ``privileged_user_ids()``;
    without it the set is built on the spot, which is fine for one account and
    wasteful for a sweep.
    """
    if user.sysadmin:
        return True
    if privileged_ids is None:
        privileged_ids = privileged_user_ids()
    return user.id in privileged_ids


def is_eligible(user, now=None, idle=None, min_age=None,
                privileged_ids=None):
    """Whether AC-2.3's criteria are all met for this account."""
    now = now or datetime.datetime.utcnow()
    idle = idle if idle is not None else idle_days()
    min_age = min_age if min_age is not None else min_account_age_days()

    if user.state != core_model.State.ACTIVE:
        return False
    if user.name and user.name.lower() in exempt_users():
        return False
    if user.sysadmin and exempt_sysadmins():
        return False
    if privileged_only() and not is_privileged(user, privileged_ids):
        return False
    if not user.created or (now - user.created).days <= min_age:
        return False

    seen = last_activity(user)
    if seen is None:
        # No creation date and no activity: too little to judge on, and the
        # age clause above should already have excluded it.
        return False
    return (now - seen).days > idle


def find_eligible(now=None, idle=None, min_age=None):
    """Every account AC-2.3 says should be disabled, oldest activity first."""
    users = (
        Session.query(core_model.User)
        .filter(core_model.User.state == core_model.State.ACTIVE)
        .all()
    )
    privileged_ids = privileged_user_ids() if privileged_only() else None
    eligible = [
        user for user in users
        if is_eligible(user, now=now, idle=idle, min_age=min_age,
                       privileged_ids=privileged_ids)
    ]
    return sorted(eligible, key=lambda user: last_activity(user)
                  or datetime.datetime.min)


def disable_inactive_users(dry_run=False, now=None, idle=None, min_age=None):
    """Disable every eligible account. Returns what was (or would be) done.

    Idempotent: a disabled account is no longer active, so a second run finds
    nothing left to do.
    """
    now = now or datetime.datetime.utcnow()
    disabled = []

    for user in find_eligible(now=now, idle=idle, min_age=min_age):
        seen = last_activity(user)
        record = {
            "id": user.id,
            "name": user.name,
            "last_active": user.last_active.isoformat()
            if user.last_active else None,
            "created": user.created.isoformat() if user.created else None,
            "idle_days": (now - seen).days if seen else None,
            # Why the account was in scope at all, so the evidence AC-2.3 asks
            # for shows the access that was retired, not just a name.
            "sysadmin": bool(user.sysadmin),
        }
        disabled.append(record)

        if dry_run:
            continue

        user.state = core_model.State.DELETED
        # Record *why*, so this disablement can be told apart from a manual
        # deletion -- the reactivation flow, the "account disabled" messages,
        # and the SSO auto-reactivation guard all key off this.
        extras = dict(user.plugin_extras or {})
        ssen = dict(extras.get("ssen") or {})
        ssen["disabled_reason"] = "inactivity"
        ssen["disabled_at"] = now.isoformat()
        extras["ssen"] = ssen
        user.plugin_extras = extras
        Session.add(user)
        # Committed per user rather than in one transaction at the end: a
        # sweep that fails half way should keep the accounts it has already
        # dealt with, and the audit line for each should be true when written.
        Session.commit()
        emit_audit_log(
            action="user_disabled",
            status="success",
            user_name=user.name,
            user_id=user.id,
            message="Account {} disabled after {} days without activity"
                    .format(user.name, record["idle_days"]),
            reason="inactivity",
            idle_days=record["idle_days"],
            last_active=record["last_active"],
        )

        if notify_dormancy() and getattr(user, "email", None):
            _send_lock_email(user)

    return disabled


# --------------------------------------------------------------------------
# Warning + lock emails (#328 item A)
# --------------------------------------------------------------------------


def notify_dormancy():
    """Whether to email users about impending / actioned disablement."""
    return toolkit.asbool(
        toolkit.config.get("ckanext.sse.inactivity.notify", True))


def _site_title():
    return toolkit.config.get("ckan.site_title", "CKAN")


def _admins_email():
    return (os.environ.get("CKANEXT__SSE__ADMINS_EMAIL")
            or toolkit.config.get("ckanext.sse.admins_email", "")).strip()


def _send_dormancy_warning(user, disable_on, days_left):
    subject = _("Your {site} account will be disabled soon").format(
        site=_site_title())
    body = _(
        "Your {site} account has not been used recently and will be disabled "
        "on {date} ({days} day(s) from now) due to inactivity.\n\n"
        "Sign in before then to keep it active."
    ).format(site=_site_title(), date=disable_on.date().isoformat(),
             days=days_left)
    try:
        mailer.mail_recipient(user.display_name or user.name, user.email,
                              subject, body)
        return True
    except Exception:
        log.exception("Could not send a dormancy warning to %s", user.name)
        return False


def _send_lock_email(user):
    admins = _admins_email()
    contact = (_(" Contact {admins} to request reactivation.")
               .format(admins=admins) if admins else "")
    subject = _("Your {site} account has been disabled").format(
        site=_site_title())
    body = _(
        "Your {site} account has been disabled due to inactivity.{contact}"
    ).format(site=_site_title(), contact=contact)
    try:
        mailer.mail_recipient(user.display_name or user.name, user.email,
                              subject, body)
    except Exception:
        log.exception("Could not send a lockout email to %s", user.name)


def _dormancy_candidate(user, now, min_age, privileged_ids):
    """Whether an account is in scope to be warned (everything but the idle
    threshold), and has an address to warn."""
    if user.state != core_model.State.ACTIVE:
        return False
    if user.name and user.name.lower() in exempt_users():
        return False
    if user.sysadmin and exempt_sysadmins():
        return False
    if privileged_only() and not is_privileged(user, privileged_ids):
        return False
    if not user.created or (now - user.created).days <= min_age:
        return False
    if last_activity(user) is None or not getattr(user, "email", None):
        return False
    return True


def _warn_markers(user):
    ssen = (user.plugin_extras or {}).get("ssen") or {}
    return bool(ssen.get("dormancy_warned_7d")), bool(
        ssen.get("dormancy_warned_1d"))


def _set_warn_markers(user, **flags):
    extras = dict(user.plugin_extras or {})
    ssen = dict(extras.get("ssen") or {})
    ssen.update(flags)
    extras["ssen"] = ssen
    user.plugin_extras = extras


def _clear_warn_markers(user):
    extras = dict(user.plugin_extras or {})
    ssen = dict(extras.get("ssen") or {})
    changed = False
    for key in ("dormancy_warned_7d", "dormancy_warned_1d"):
        if key in ssen:
            ssen.pop(key)
            changed = True
    if changed:
        extras["ssen"] = ssen
        user.plugin_extras = extras
    return changed


def send_dormancy_warnings(dry_run=False, now=None, idle=None, min_age=None):
    """Email accounts approaching disablement, once per threshold crossed.

    Idempotent via ``dormancy_warned_*`` markers, which are cleared once an
    account is active enough again -- so a later dormancy episode warns afresh.
    Window-matched: if a run is missed, the next one still sends the warning
    for the threshold that was skipped (a missed 7-day warning becomes the
    1-day one). Returns what was (or would be) sent.
    """
    if not notify_dormancy():
        return []
    now = now or datetime.datetime.utcnow()
    idle = idle if idle is not None else idle_days()
    min_age = min_age if min_age is not None else min_account_age_days()
    longest = max(DORMANCY_WARN_DAYS)

    privileged_ids = privileged_user_ids() if privileged_only() else None
    users = (
        Session.query(core_model.User)
        .filter(core_model.User.state == core_model.State.ACTIVE)
        .all()
    )

    warned = []
    for user in users:
        if not _dormancy_candidate(user, now, min_age, privileged_ids):
            continue

        current_idle = (now - last_activity(user)).days
        if current_idle < idle - longest:
            # Not approaching. Reset stale markers so a future episode warns.
            if not dry_run and _clear_warn_markers(user):
                Session.commit()
            continue
        if current_idle >= idle:
            continue  # already eligible: the disable pass sends the lock email

        days_left = idle - current_idle
        disable_on = last_activity(user) + datetime.timedelta(days=idle)
        warned_7d, warned_1d = _warn_markers(user)

        if days_left <= 1 and not warned_1d:
            if not dry_run and _send_dormancy_warning(user, disable_on,
                                                      days_left):
                _set_warn_markers(user, dormancy_warned_1d=True,
                                  dormancy_warned_7d=True)
                Session.commit()
            warned.append({"name": user.name, "days_left": days_left,
                           "kind": "1d"})
        elif 1 < days_left <= longest and not warned_7d:
            if not dry_run and _send_dormancy_warning(user, disable_on,
                                                      days_left):
                _set_warn_markers(user, dormancy_warned_7d=True)
                Session.commit()
            warned.append({"name": user.name, "days_left": days_left,
                           "kind": "7d"})

    return warned


# --------------------------------------------------------------------------
# Reactivation (sysadmin, #328 item C)
# --------------------------------------------------------------------------


def inactivity_disabled_users():
    """Every account currently disabled by the dormancy sweep."""
    return (
        Session.query(core_model.User)
        .filter(
            core_model.User.state == core_model.State.DELETED,
            core_model.User.plugin_extras["ssen"]["disabled_reason"].astext
            == "inactivity",
        )
        .order_by(core_model.User.name)
        .all()
    )


def reactivate(name):
    """Restore an inactivity-disabled account. Returns the user, or ``None``.

    Two things are load-bearing here:

    * ``last_active`` is reset to now, or the next sweep would re-disable the
      account immediately (its activity timestamp is still old); and
    * ``disabled_reason`` (and the other dormancy markers) are cleared, or the
      SSO-reactivation guard below would re-disable it on the next request.

    This is the *only* sanctioned way back from an inactivity disablement.
    """
    user = core_model.User.get(name)
    if user is None:
        return None

    # Only inactivity disablements come back this way. ``User.get`` returns
    # soft-deleted users, so without this an account disabled for another reason
    # -- a manual deletion, or an Entra-driven deactivation -- could be brought
    # back through the dormancy admin form, bypassing the proper path.
    if (user.state != core_model.State.DELETED
            or _ssen_extras(user).get("disabled_reason") != "inactivity"):
        return None

    user.state = core_model.State.ACTIVE
    user.last_active = datetime.datetime.utcnow()

    extras = dict(user.plugin_extras or {})
    ssen = dict(extras.get("ssen") or {})
    for key in ("disabled_reason", "disabled_at", "reactivation_requested_at"):
        ssen.pop(key, None)
    for key in [k for k in ssen if k.startswith("dormancy_warned")]:
        ssen.pop(key, None)
    extras["ssen"] = ssen
    user.plugin_extras = extras

    Session.commit()

    emit_audit_log(
        action="user_reactivated",
        status="success",
        user_name=user.name,
        user_id=user.id,
        message="Account {} reactivated".format(user.name),
        reason="admin_reactivation",
    )
    return user


# --------------------------------------------------------------------------
# Guard against silent reactivation of an inactivity-disabled account (#331/N)
# --------------------------------------------------------------------------
#
# ``ckanext-oauth2`` reactivates any existing user it finds on SSO login
# (``user_json`` sets ``state='active'``), which would silently undo an AC-2.3
# disablement the moment the holder signed in with Azure -- no sysadmin review,
# the reactivation-request flow bypassed. CKAN core's ``User.by_email`` returns
# deleted users, so this reaches disabled accounts too.
#
# Rather than fork the SSO extension, this catches the *state* it leaves: an
# account that is active yet still carries ``disabled_reason='inactivity'`` was
# reactivated without going through the proper flow (which clears the flag). It
# is put straight back to disabled and sent to the login page with the reason.


def _ssen_extras(user):
    extras = getattr(user, "plugin_extras", None) or {}
    return extras.get("ssen") or {}


def enforce_disabled_reactivation():
    """Re-disable an inactivity-disabled account reactivated out-of-band.

    Returns a redirect when it acts, ``None`` otherwise. Must not raise: it runs
    before every request.
    """
    try:
        return _enforce_disabled_reactivation()
    except Exception:
        log.exception("Reactivation guard failed; allowing the request")
        return None


def _enforce_disabled_reactivation():
    if not has_request_context():
        return None

    user = toolkit.current_user
    if user is None or getattr(user, "is_anonymous", True):
        return None
    if getattr(user, "state", None) != core_model.State.ACTIVE:
        return None
    if _ssen_extras(user).get("disabled_reason") != "inactivity":
        return None

    # The action API authenticates with tokens, not this SSO session, and a
    # token for a deleted user will not authenticate anyway. Keyed on the path,
    # not request.endpoint, which is not reliably populated this early. Asset
    # requests are not exempted -- acting on one is harmless (the guard is a
    # one-shot: it re-disables, and every later request then sees state !=
    # active and returns early).
    if toolkit.request.path.startswith("/api/"):
        return None

    db_user = core_model.User.get(user.id)
    if db_user is not None:
        db_user.state = core_model.State.DELETED
        Session.commit()

    emit_audit_log(
        action="user_login",
        status="failure",
        user_name=getattr(user, "name", None),
        user_id=getattr(user, "id", None),
        message="Blocked out-of-band reactivation of inactivity-disabled "
                "account {}".format(getattr(user, "name", "unknown")),
        reason="inactivity_disabled",
    )

    logout_user()
    toolkit.h.flash_error(
        _("Your account is disabled due to inactivity. Please request "
          "reactivation or contact the site administrators.")
    )
    return toolkit.redirect_to("user.login")


# --------------------------------------------------------------------------
# CKAN-native login: explain an inactivity disablement (#328 item G)
# --------------------------------------------------------------------------
#
# CKAN's own login returns a generic "bad username or password" for a deleted
# account. On a login POST whose submitted name matches an inactivity-disabled
# account, flash the real reason and bounce back to the form before the
# credentials are even checked. (The decoupled frontend has its own path -- see
# user_login's disabled_reason.)


def enforce_disabled_login_message():
    """Explain, on the CKAN login form, that an account is disabled. Returns a
    redirect when it acts, else ``None``. Must not raise."""
    try:
        return _enforce_disabled_login_message()
    except Exception:
        log.exception("Disabled-login message check failed; allowing request")
        return None


def _enforce_disabled_login_message():
    if not has_request_context():
        return None
    # Path, not endpoint (endpoint is unreliable this early). Login POST only.
    if toolkit.request.method != "POST":
        return None
    if not toolkit.request.path.rstrip("/").endswith("/user/login"):
        return None

    login = toolkit.request.form.get("login")
    if not login:
        return None
    user = (core_model.User.by_name(login)
            or core_model.User.by_email(login))
    if user is None:
        return None
    ssen = (user.plugin_extras or {}).get("ssen") or {}
    if (user.state != core_model.State.DELETED
            or ssen.get("disabled_reason") != "inactivity"):
        return None

    toolkit.h.flash_error(
        _("This account has been disabled due to inactivity. Request "
          "reactivation below, or contact the site administrators.")
    )
    # Send them to the request page (prefilled) rather than a dead-end form.
    return toolkit.redirect_to(
        "sse_account_lifecycle.request_reactivation_form", login=login)


# --------------------------------------------------------------------------
# Self-service reactivation request (#328 item G)
# --------------------------------------------------------------------------
#
# A dormant account cannot sign in, so the request must be reachable while
# anonymous. It only records a marker a sysadmin still approves, and always
# answers the same way so it cannot be used to tell which accounts exist or
# are disabled. ``/user/request-reactivation`` must be on the noanonaccess
# allowlist or this 302s to login.


def record_reactivation_request(login):
    """Flag an inactivity-disabled account as having requested reactivation.

    Matches on username or email (case-insensitive). A no-op for any other
    account, and never reveals whether a match was found. Safe to call
    anonymously; must not raise.
    """
    login = (login or "").strip()
    if not login:
        return
    try:
        user = (core_model.User.by_name(login)
                or core_model.User.by_email(login))
        # by_email can return a list on some CKAN versions.
        if isinstance(user, list):
            user = user[0] if user else None
        if user is None:
            return
        ssen = (user.plugin_extras or {}).get("ssen") or {}
        if (user.state != core_model.State.DELETED
                or ssen.get("disabled_reason") != "inactivity"):
            return
        # Single request per disablement: don't re-stamp or re-audit. The
        # marker is cleared on reactivation, so a later dormancy can request
        # again.
        if ssen.get("reactivation_requested_at"):
            return
        extras = dict(user.plugin_extras or {})
        marked = dict(extras.get("ssen") or {})
        marked["reactivation_requested_at"] = \
            datetime.datetime.utcnow().isoformat()
        extras["ssen"] = marked
        user.plugin_extras = extras
        Session.add(user)
        Session.commit()
        emit_audit_log(
            action="reactivation_requested",
            status="success",
            user_name=user.name,
            user_id=user.id,
            message="Reactivation requested for {}".format(user.name),
            reason="self_service",
        )
    except Exception:
        log.exception("Recording a reactivation request failed")


def request_reactivation_form():
    """The self-service request page."""
    return toolkit.render(
        "user/request_reactivation.html",
        extra_vars={"login": toolkit.request.args.get("login", "")},
    )


def submit_reactivation_request():
    record_reactivation_request(toolkit.request.form.get("login"))
    # Neutral: identical whether or not an account matched.
    toolkit.h.flash_success(
        _("If an account with that username or email is disabled for "
          "inactivity, a reactivation request has been recorded for an "
          "administrator to review."))
    return toolkit.redirect_to("user.login")


# Routeless guards + the self-service request route.
blueprint = Blueprint("sse_account_lifecycle", __name__)

blueprint.add_url_rule(
    "/user/request-reactivation", methods=["GET"],
    view_func=request_reactivation_form)
blueprint.add_url_rule(
    "/user/request-reactivation", methods=["POST"],
    view_func=submit_reactivation_request)


@blueprint.before_app_request
def _before_app_request():
    # Anonymous login attempt against a disabled account: explain why.
    response = enforce_disabled_login_message()
    if response is not None:
        return response
    # Authenticated request on an account reactivated out-of-band: re-disable.
    return enforce_disabled_reactivation()
