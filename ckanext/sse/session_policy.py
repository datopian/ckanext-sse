"""Idle session timeout (AC-2.5, AC-11).

AC-11 requires a device lock "after 15 minutes of inactivity", retained "until
the user re-establishes access using established identification and
authentication procedures"; AC-2.5 requires users to log off when they finish
work. Both are written for a workstation. The portal cannot lock a device, so
the control it *can* implement is the compensating one: an idle session is
ended and the user has to sign in again.

Kept separate from the password policy because it is a different control with
a different trigger, but it runs from the same kind of ``before_app_request``
handler and must run *before* the password rotation check -- a session that
has already timed out should be sent to the login form, not told to change its
password.

Only signed-in browser sessions are affected. Anonymous browsing has no
session to end, and the action API is exempt for the same reason it is exempt
from rotation: an API token is a separate credential, and a client presenting
one is not idle at a screen.

The last-seen stamp is only rewritten once a minute. Beaker sends a
``Set-Cookie`` whenever the session changes, so stamping every request would
add one to every response on the site, including every asset.

There are two independent timers, and a session ends at whichever fires first:

* an **idle** timeout (AC-11) -- 15 minutes since the last request; and
* an **absolute** cap (AC-12) -- 8 hours since sign-in, regardless of activity,
  after which the user must re-authenticate. This applies to every session
  however it was authenticated (local password or Azure AD SSO); how gracefully
  the provider re-authenticates is the provider's business.

Configuration
-------------

=============================================== ==========================
``ckanext.sse.session.idle_timeout_minutes``    15 (0 disables)
``ckanext.sse.session.max_session_hours``       8 (0 disables)
=============================================== ==========================
"""

import logging
import time

from flask import Blueprint, has_request_context
from flask_login import logout_user, user_logged_in

import ckan.plugins.toolkit as toolkit
from ckan.common import session

from ckanext.sse.audit import emit_audit_log

log = logging.getLogger(__name__)

_ = toolkit._

# AC-11 a: "initiating a device lock after 15 minutes of inactivity".
DEFAULT_IDLE_TIMEOUT_MINUTES = 15

# AC-12: terminate a session after a maximum of 8 hours, regardless of
# activity, so a refresh cannot extend it past this absolute limit.
DEFAULT_MAX_SESSION_HOURS = 8

# How stale the stamp may get before it is rewritten. Anything below the
# timeout is safe; a minute keeps the write rate down without meaningfully
# shortening the window.
STAMP_INTERVAL_SECONDS = 60

SESSION_KEY = "sse_last_seen"

# When the session was established. Set at sign-in and never refreshed -- the
# absolute cap is measured from it.
SESSION_START_KEY = "sse_session_start"


def idle_timeout_seconds():
    """The idle window in seconds. 0 disables the timeout."""
    raw = toolkit.config.get("ckanext.sse.session.idle_timeout_minutes",
                             DEFAULT_IDLE_TIMEOUT_MINUTES)
    try:
        minutes = toolkit.asint(raw)
    except (ValueError, TypeError):
        log.warning("Ignoring invalid ckanext.sse.session."
                    "idle_timeout_minutes %r, using %s", raw,
                    DEFAULT_IDLE_TIMEOUT_MINUTES)
        minutes = DEFAULT_IDLE_TIMEOUT_MINUTES
    return max(0, minutes) * 60


def max_session_seconds():
    """The absolute session cap in seconds. 0 disables it."""
    raw = toolkit.config.get("ckanext.sse.session.max_session_hours",
                             DEFAULT_MAX_SESSION_HOURS)
    try:
        hours = toolkit.asint(raw)
    except (ValueError, TypeError):
        log.warning("Ignoring invalid ckanext.sse.session.max_session_hours "
                    "%r, using %s", raw, DEFAULT_MAX_SESSION_HOURS)
        hours = DEFAULT_MAX_SESSION_HOURS
    return max(0, hours) * 3600


def get_subscriptions():
    return {user_logged_in: [on_user_logged_in]}


def on_user_logged_in(sender, user=None, **kwargs):
    """Stamp when the session began, so the absolute cap resets each sign-in.

    A fresh stamp per login matters: Beaker may keep the same session across a
    logout/login, and without this a new session would inherit the old start
    and be capped early.
    """
    try:
        session[SESSION_START_KEY] = int(time.time())
    except Exception:
        log.debug("Could not stamp the session start time")


def enforce_absolute_timeout():
    """End a session older than the absolute cap, whatever its activity.

    Returns a redirect to the login page when the session is ended, ``None``
    otherwise. Nothing here may raise: it runs before every request.
    """
    try:
        return _enforce_absolute_timeout()
    except Exception:
        log.exception("Absolute session check failed; allowing the request")
        return None


def _enforce_absolute_timeout():
    limit = max_session_seconds()
    if not limit or not has_request_context():
        return None

    user = toolkit.current_user
    if user is None or getattr(user, "is_anonymous", True):
        return None

    if toolkit.request.path.startswith("/api/"):
        return None

    blueprint = (toolkit.request.endpoint or "").split(".")[0]
    if blueprint in ("static", "webassets", "_debug_toolbar"):
        return None

    now = int(time.time())
    try:
        start = session.get(SESSION_START_KEY)
    except Exception:
        return None

    if not start:
        # A session that predates this feature, or was not stamped at login:
        # start the window now rather than signing everyone out on deploy.
        try:
            session[SESSION_START_KEY] = now
        except Exception:
            log.debug("Could not stamp the session start time")
        return None

    if now - int(start) > limit:
        return _end_session(user, limit, absolute=True)
    return None


def enforce_idle_timeout():
    """End a session that has been idle too long.

    Returns a redirect to the login page when the session is ended, ``None``
    otherwise. Nothing here may raise: it runs before every request.
    """
    try:
        return _enforce_idle_timeout()
    except Exception:
        log.exception("Idle session check failed; allowing the request")
        return None


def _enforce_idle_timeout():
    timeout = idle_timeout_seconds()
    if not timeout or not has_request_context():
        return None

    user = toolkit.current_user
    if user is None or getattr(user, "is_anonymous", True):
        return None

    if toolkit.request.path.startswith("/api/"):
        return None

    # Assets are skipped so that the request that gets the message is the
    # page the user was looking at, not the stylesheet next to it.
    blueprint = (toolkit.request.endpoint or "").split(".")[0]
    if blueprint in ("static", "webassets", "_debug_toolbar"):
        return None

    now = int(time.time())
    try:
        last_seen = session.get(SESSION_KEY)
    except Exception:
        # No usable session, so there is no idle window to measure.
        return None

    if last_seen and now - int(last_seen) > timeout:
        return _end_session(user, timeout)

    if not last_seen or now - int(last_seen) > STAMP_INTERVAL_SECONDS:
        try:
            session[SESSION_KEY] = now
        except Exception:
            log.debug("Could not stamp the session activity time")
    return None


def _end_session(user, timeout, absolute=False):
    name = getattr(user, "name", None)
    if absolute:
        message = "Session for {} ended after {} seconds (absolute cap)".format(
            name or "unknown", timeout)
        reason = "absolute_timeout"
    else:
        message = "Session for {} ended after {} seconds idle".format(
            name or "unknown", timeout)
        reason = "idle_timeout"
    emit_audit_log(
        action="user_logout",
        status="success",
        user_name=name,
        user_id=getattr(user, "id", None),
        message=message,
        reason=reason,
        timeout_seconds=timeout,
    )

    logout_user()
    # Not ``session.clear()``: the flash below has to survive into the next
    # request, and flask-login has already removed what identifies the user.
    try:
        session.pop(SESSION_KEY, None)
        session.pop(SESSION_START_KEY, None)
    except Exception:
        pass

    if absolute:
        toolkit.h.flash_notice(
            _("You were signed out after {hours} hours. Please sign in "
              "again.").format(hours=timeout // 3600)
        )
    else:
        toolkit.h.flash_notice(
            _("You were signed out after {minutes} minutes of inactivity. "
              "Please sign in again.").format(minutes=timeout // 60)
        )
    return toolkit.redirect_to("user.login",
                               came_from=toolkit.request.path)


# Routeless: it exists only to hang the session checks off
# ``before_app_request``.
blueprint = Blueprint("sse_session_policy", __name__)


@blueprint.before_app_request
def _before_app_request():
    # Absolute cap first: an over-8h session should be sent to the login form
    # even if it is also within the idle window.
    response = enforce_absolute_timeout()
    if response is not None:
        return response
    return enforce_idle_timeout()
