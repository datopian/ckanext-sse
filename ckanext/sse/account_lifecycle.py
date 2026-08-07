"""Disablement of dormant accounts (AC-2.3).

SSE's *Standard for Access Control* AC-2.3 requires accounts to be disabled
automatically once they are "eligible for disablement", which it defines as:

* last logon greater than 45 days ago;
* creation date greater than 30 days ago;
* not in any "Admin Disablement" AD group.

The second clause is what stops a newly issued account being disabled before
its holder has had a chance to use it, and the third is the exemption list for
accounts that are supposed to sit idle. Here that is
``ckanext.sse.inactivity.exempt_users`` plus, by default, sysadmins -- an
automated sweep that disables every administrator during a quiet month would
leave nobody able to undo it.

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
``ckanext.sse.inactivity.exempt_sysadmins``           true
``ckanext.sse.inactivity.exempt_users``               names, space separated
===================================================== ====================
"""

import datetime
import logging
import re

import ckan.model as core_model
import ckan.plugins.toolkit as toolkit
from ckan.model.meta import Session

from ckanext.sse.audit import emit_audit_log

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
    return toolkit.asbool(
        toolkit.config.get("ckanext.sse.inactivity.exempt_sysadmins", True)
    )


def last_activity(user):
    """When this account was last used, falling back to its creation."""
    return user.last_active or user.created


def is_eligible(user, now=None, idle=None, min_age=None):
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
    eligible = [
        user for user in users
        if is_eligible(user, now=now, idle=idle, min_age=min_age)
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
        }
        disabled.append(record)

        if dry_run:
            continue

        user.state = core_model.State.DELETED
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

    return disabled
