"""Account lockout after repeated failed logins (AC-7).

SSE's *Standard for Access Control* AC-7 requires a limit of six consecutive
invalid logon attempts by a user, and that the account is then locked "for 30
minutes or until released by an administrator". CKAN has no lockout of any
kind: an unlimited number of guesses can be made against any account.

The mechanism follows ``ckanext-security``: two Redis keys per account, a
counter and a lock, both carrying their own expiry so nothing has to be swept
up afterwards. Redis rather than a table because the state is short-lived by
definition, an expiring key *is* the 30-minute timer, and ``INCR`` is atomic
across workers where a read-modify-write against Postgres would not be.

Where this departs from ``ckanext-security`` is the hook, and for a concrete
reason. That extension counts attempts from ``IAuthenticator.authenticate()``,
which calls ``default_authenticate()`` itself and returns ``None`` when the
credentials are wrong. ``ckan_authenticator`` (``ckan/lib/authenticator.py``)
reads ``None`` as "this plugin has no opinion" and falls through to
``default_authenticate()`` a second time, so every failed login is
authenticated twice and emits the ``failed_login`` signal twice -- which this
deployment records in its audit trail. Counting from the signal instead, and
blocking from a ``before_app_request`` handler that runs before the login view,
keeps one attempt to one event.

Two consequences of counting from the signal are worth knowing:

* ``failed_login`` also fires for the old-password check on the profile form
  (``EditView`` authenticates before it will change a password), so receivers
  are filtered to the login endpoint. Mistyping your current password while
  changing it is not a logon attempt and must not lock the account.
* The lock is checked before the view runs, so it applies whether or not the
  credentials presented during the lock are correct.

Keyed on the account, which is what the standard asks for and what makes the
limit meaningful -- an attacker changing address every attempt would defeat a
per-address counter. The cost is that a third party can lock a known account
out by failing six times against it. That is inherent in an account-lockout
control, and the 30-minute expiry bounds it.

An attempt against a login that matches no account is counted under whatever
was typed, so spraying does not get an unlimited budget against nonexistent
names either.

Redis being unavailable fails *open*: the attempt is allowed and an error is
logged. The alternative is an outage in a cache locking every user out of the
portal.

Configuration
-------------

=============================================== ==========================
``ckanext.sse.login.max_attempts``              6
``ckanext.sse.login.lockout_minutes``           30
``ckanext.sse.login.attempt_window_minutes``    30
``ckanext.sse.login.notify_lockout``            true
=============================================== ==========================
"""

import logging

from flask import Blueprint, has_request_context
from flask_login import user_logged_in

import ckan.lib.mailer as mailer
import ckan.model as core_model
import ckan.plugins.toolkit as toolkit
from ckan.lib.redis import connect_to_redis

from ckanext.sse.audit import emit_audit_log

log = logging.getLogger(__name__)

_ = toolkit._

# AC-7 a: "Enforce a limit of six consecutive invalid logon attempts by a
# user".
DEFAULT_MAX_ATTEMPTS = 6

# AC-7 b: "Automatically lock the account for 30 minutes or until released by
# an administrator".
DEFAULT_LOCKOUT_MINUTES = 30

# How long a failure is remembered. The standard says "consecutive" without
# bounding the gap; an attempt an hour after the last one is not really part
# of the same run, and without an expiry a counter left at five would lock an
# account on a single typo months later.
DEFAULT_ATTEMPT_WINDOW_MINUTES = 30

# The endpoint whose failures count. Deliberately not every call to CKAN's
# authenticator -- see the module docstring.
LOGIN_ENDPOINT = "user.login"

FAILURE_KEY = "sse:login:failures:{}"
LOCK_KEY = "sse:login:lock:{}"


def get_subscriptions():
    return {
        toolkit.signals.failed_login: [on_failed_login],
        user_logged_in: [on_user_logged_in],
    }


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------


def _int_config(key, default, minimum=1):
    raw = toolkit.config.get(key, default)
    try:
        value = toolkit.asint(raw)
    except (ValueError, TypeError):
        log.warning("Ignoring invalid %s %r, using %s", key, raw, default)
        return default
    return max(minimum, value)


def max_attempts():
    return _int_config("ckanext.sse.login.max_attempts",
                       DEFAULT_MAX_ATTEMPTS)


def lockout_seconds():
    return _int_config("ckanext.sse.login.lockout_minutes",
                       DEFAULT_LOCKOUT_MINUTES) * 60


def attempt_window_seconds():
    return _int_config("ckanext.sse.login.attempt_window_minutes",
                       DEFAULT_ATTEMPT_WINDOW_MINUTES) * 60


def notify_on_lockout():
    return toolkit.asbool(
        toolkit.config.get("ckanext.sse.login.notify_lockout", True)
    )


# --------------------------------------------------------------------------
# State
# --------------------------------------------------------------------------


def throttle_key(login):
    """The account an attempt counts against.

    Resolved through the user table so that ``jbloggs`` and
    ``joe@example.com`` share one budget rather than two -- CKAN accepts
    either at the login form. An attempt against a login matching no account
    is counted under what was typed, lower-cased so case cannot multiply the
    budget either.
    """
    if not login or not isinstance(login, str):
        return None
    login = login.strip()
    if not login:
        return None

    user = core_model.User.by_name(login) or core_model.User.by_email(login)
    if user is not None:
        return user.name
    return login.lower()


def _redis():
    return connect_to_redis()


def is_locked(key):
    """Whether this account is inside its lockout window."""
    if not key:
        return False
    try:
        return bool(_redis().exists(LOCK_KEY.format(key)))
    except Exception:
        # Failing open: see the module docstring.
        log.exception("Login lockout check failed; allowing the attempt")
        return False


def lock_seconds_remaining(key):
    """Seconds left on the lock, or 0. For the message shown to the user."""
    try:
        return max(0, int(_redis().ttl(LOCK_KEY.format(key)) or 0))
    except Exception:
        return 0


def record_failure(key, user=None):
    """Count one failed attempt, locking the account once the limit is hit.

    Returns the running count, or ``None`` if the count could not be kept.
    """
    if not key:
        return None
    try:
        redis = _redis()
        failures = FAILURE_KEY.format(key)
        count = redis.incr(failures)
        if count == 1:
            # Only the first failure sets the expiry, so a run of attempts is
            # measured from its start rather than being extended indefinitely
            # by the attacker's own traffic.
            redis.expire(failures, attempt_window_seconds())
        if count >= max_attempts():
            _lock(key, user)
            redis.delete(failures)
        return count
    except Exception:
        log.exception("Could not record a failed login for %s", key)
        return None


def _lock(key, user):
    seconds = lockout_seconds()
    _redis().set(LOCK_KEY.format(key), "1", ex=seconds)

    emit_audit_log(
        action="user_lockout",
        status="failure",
        user_name=getattr(user, "name", None) or key,
        user_id=getattr(user, "id", None),
        message="Account {} locked for {} seconds after {} failed login "
                "attempts".format(key, seconds, max_attempts()),
        lockout_seconds=seconds,
        failed_attempts=max_attempts(),
        # An attempt against a name that matches no account is still worth
        # recording, and worth being able to tell apart from a real one.
        account_exists=user is not None,
    )

    if user is not None and notify_on_lockout():
        _notify(user, seconds)


def _notify(user, seconds):
    """Tell the account holder their account has been locked.

    They are the one person who can tell an attack from their own typo, and
    the lock is otherwise invisible until they next try to sign in. Failure to
    send must not prevent the lock.
    """
    try:
        mailer.mail_recipient(
            user.display_name or user.name,
            user.email,
            _("Your {site} account has been locked").format(
                site=toolkit.config.get("ckan.site_title", "CKAN")),
            _("Your account was locked for {minutes} minutes after {n} "
              "failed sign-in attempts.\n\n"
              "If this was you, you can sign in again once that time has "
              "passed, or reset your password.\n\n"
              "If it was not you, someone is trying to guess your password. "
              "Please contact the site administrators.").format(
                  minutes=seconds // 60, n=max_attempts()),
        )
    except Exception:
        log.exception("Could not send a lockout notification to %s", user.name)


def clear(key):
    """Release a lock and forget the failures. Used by the CLI."""
    try:
        redis = _redis()
        removed = redis.delete(LOCK_KEY.format(key))
        redis.delete(FAILURE_KEY.format(key))
        return bool(removed)
    except Exception:
        log.exception("Could not clear the login lock for %s", key)
        return False


def status(key):
    """Failure count and remaining lock time, for the CLI."""
    try:
        redis = _redis()
        raw = redis.get(FAILURE_KEY.format(key))
        return {
            "key": key,
            "failures": int(raw) if raw else 0,
            "locked": bool(redis.exists(LOCK_KEY.format(key))),
            "seconds_remaining": lock_seconds_remaining(key),
        }
    except Exception:
        log.exception("Could not read the login state for %s", key)
        return {"key": key, "failures": 0, "locked": False,
                "seconds_remaining": 0}


# --------------------------------------------------------------------------
# Hooks
# --------------------------------------------------------------------------


def _is_login_attempt():
    """Whether this request is a submission of the login form."""
    return (
        has_request_context()
        and toolkit.request.endpoint == LOGIN_ENDPOINT
        and toolkit.request.method == "POST"
    )


def on_failed_login(sender, **kwargs):
    """CKAN's ``failed_login``: the attempted login name is the sender."""
    try:
        if not _is_login_attempt():
            return
        login = sender if isinstance(sender, str) else None
        key = throttle_key(login)
        if key is None:
            return
        user = core_model.User.by_name(key)
        record_failure(key, user)
    except Exception:
        log.exception("Failed to record a login failure")


def on_user_logged_in(sender, user=None, **kwargs):
    """A successful login ends the run, which is what "consecutive" means."""
    try:
        name = getattr(user, "name", None)
        if name:
            clear(name)
    except Exception:
        log.exception("Failed to reset the login failure count")


def check_login_lock():
    """Refuse a login submission while the account is locked.

    Runs before the login view, so the credentials presented are never
    checked and a correct password does not shorten the lockout.

    Nothing here may raise: it runs before every request.
    """
    try:
        if not _is_login_attempt():
            return None

        key = throttle_key(toolkit.request.form.get("login"))
        if key is None or not is_locked(key):
            return None

        minutes = max(1, lock_seconds_remaining(key) // 60)
        toolkit.h.flash_error(
            _("Too many failed sign-in attempts. This account is locked for "
              "another {minutes} minute(s). Contact the site administrators "
              "if you need access sooner.").format(minutes=minutes)
        )
        emit_audit_log(
            action="user_login",
            status="failure",
            user_name=key,
            message="Login attempt for locked account {}".format(key),
            locked_out=True,
        )
        return toolkit.redirect_to(LOGIN_ENDPOINT)
    except Exception:
        log.exception("Login lock check failed; allowing the request")
        return None


# Routeless: it exists only to hang the lock check off ``before_app_request``.
# See ``ckanext.sse.password_policy`` for why an IAuthenticator hook is not
# used for this kind of check.
blueprint = Blueprint("sse_login_throttle", __name__)


@blueprint.before_app_request
def _before_app_request():
    return check_login_lock()
