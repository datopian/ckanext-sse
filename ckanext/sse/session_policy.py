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

Configuration
-------------

=============================================== ==========================
``ckanext.sse.session.idle_timeout_minutes``    15 (0 disables)
=============================================== ==========================
"""

import logging
import time

from flask import Blueprint, has_request_context
from flask_login import logout_user

import ckan.plugins.toolkit as toolkit
from ckan.common import session

from ckanext.sse.audit import emit_audit_log

log = logging.getLogger(__name__)

_ = toolkit._

# AC-11 a: "initiating a device lock after 15 minutes of inactivity".
DEFAULT_IDLE_TIMEOUT_MINUTES = 15

# How stale the stamp may get before it is rewritten. Anything below the
# timeout is safe; a minute keeps the write rate down without meaningfully
# shortening the window.
STAMP_INTERVAL_SECONDS = 60

SESSION_KEY = "sse_last_seen"


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


def _end_session(user, timeout):
    name = getattr(user, "name", None)
    emit_audit_log(
        action="user_logout",
        status="success",
        user_name=name,
        user_id=getattr(user, "id", None),
        message="Session for {} ended after {} seconds idle".format(
            name or "unknown", timeout),
        reason="idle_timeout",
        idle_timeout_seconds=timeout,
    )

    logout_user()
    # Not ``session.clear()``: the flash below has to survive into the next
    # request, and flask-login has already removed what identifies the user.
    try:
        session.pop(SESSION_KEY, None)
    except Exception:
        pass

    toolkit.h.flash_notice(
        _("You were signed out after {minutes} minutes of inactivity. "
          "Please sign in again.").format(minutes=timeout // 60)
    )
    return toolkit.redirect_to("user.login",
                               came_from=toolkit.request.path)


# Routeless: it exists only to hang the idle check off ``before_app_request``.
blueprint = Blueprint("sse_session_policy", __name__)


@blueprint.before_app_request
def _before_app_request():
    return enforce_idle_timeout()
