"""Structured security audit logging for authentication events.

Emits one JSON object per event, one line each, straight to stdout for the
centralised log collector to pick up.

Deliberately not routed through the stdlib logger: CKAN's ``[handler_console]``
writes to ``sys.stderr``, and GKE's logging agent tags stderr output as
``severity: ERROR``, which would file every successful login as an error.
Writing to stdout ourselves also means a change to CKAN's log levels cannot
silence the audit trail. The logger is still used for failures to *emit* an
event, where stderr and an ERROR severity are the right destination.

The hooks used here were chosen against the semantics CKAN actually
implements (2.10):

``IAuthenticator.login()`` is *not* a success hook -- CKAN calls it at the top
of the login view, before the credentials are even asked for
(``ckan/views/user.py``), so it fires on a plain GET of the login page with an
anonymous user. Successful logins are captured through flask-login's
``user_logged_in`` signal, which ``login_user()`` sends once the user object
has been established. Failures come from CKAN's own ``failed_login`` signal
(``ckan/lib/authenticator.py``).
"""

import datetime
import json
import logging
import sys

from flask import has_request_context
from flask_login import user_logged_in

import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit

log = logging.getLogger(__name__)

EVENT_TYPE = "security_audit"

# Number of trusted proxies that append to X-Forwarded-For. A single GCP
# external HTTP(S) load balancer appends one entry, so the client address is
# the second from the right; anything further left is client-supplied and
# therefore spoofable.
DEFAULT_TRUSTED_PROXIES = 1


def get_subscriptions():
    return {
        user_logged_in: [on_user_logged_in],
        toolkit.signals.failed_login: [on_failed_login],
    }


def on_user_logged_in(sender, user=None, **kwargs):
    """flask-login ``user_logged_in``: sender is the app, ``user`` the User."""
    emit_audit_log(
        action="user_login",
        status="success",
        user_name=getattr(user, "name", None),
        user_id=getattr(user, "id", None),
        message="Successful login for user {}".format(
            getattr(user, "name", "unknown")
        ),
    )


def on_failed_login(sender, **kwargs):
    """CKAN ``failed_login``: the attempted login name is the *sender*."""
    attempted = sender if isinstance(sender, str) else None
    emit_audit_log(
        action="user_login",
        status="failure",
        user_name=attempted,
        message="Failed login attempt for {}".format(attempted or "unknown"),
    )


def _request_context():
    """Network context for the current request, empty outside of one."""
    if not has_request_context():
        return {}

    environ = toolkit.request.environ
    forwarded_for = environ.get("HTTP_X_FORWARDED_FOR")
    remote_addr = environ.get("REMOTE_ADDR")

    return {
        "source_ip": _client_ip(forwarded_for, remote_addr),
        "forwarded_for": forwarded_for,
        "remote_addr": remote_addr,
        "user_agent": environ.get("HTTP_USER_AGENT"),
        "request_path": toolkit.request.path,
    }


def _client_ip(forwarded_for, remote_addr):
    """Pick the client address out of the X-Forwarded-For chain.

    The raw chain is logged alongside this, so a wrong
    ``ckanext.sse.audit.trusted_proxies`` setting loses no information.
    """
    if not forwarded_for:
        return remote_addr

    chain = [part.strip() for part in forwarded_for.split(",") if part.strip()]
    if not chain:
        return remote_addr

    trusted = toolkit.asint(
        toolkit.config.get(
            "ckanext.sse.audit.trusted_proxies", DEFAULT_TRUSTED_PROXIES
        )
    )
    index = len(chain) - 1 - trusted
    if index < 0:
        # Fewer hops than configured -- the leftmost entry is the best guess.
        return chain[0]
    return chain[index]


def emit_audit_log(action, status, message, user_name=None, user_id=None):
    payload = {
        "event_type": EVENT_TYPE,
        # Event time, not ingestion time -- the collector's own clock can lag
        # behind under load, and there is no log formatter supplying one here.
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "action": action,
        "status": status,
        "user_name": user_name or "anonymous",
        "user_id": user_id,
        "message": message,
    }
    payload.update(_request_context())

    # A broken audit line must never break the request it describes. Failures
    # go to the logger (stderr), where an ERROR severity is accurate.
    try:
        print(json.dumps(payload), file=sys.stdout, flush=True)
    except Exception:
        log.exception("Failed to emit security audit log for %s", action)


class SecurityAuditPlugin(plugins.SingletonPlugin):
    """Logs authentication events as structured JSON."""

    plugins.implements(plugins.IAuthenticator, inherit=True)
    plugins.implements(plugins.ISignal)

    # ISignal
    def get_signal_subscriptions(self):
        return get_subscriptions()

    # IAuthenticator
    def logout(self):
        """Called before the logout runs, so the user is still authenticated.

        Returns None to leave CKAN's logout flow untouched.
        """
        user = toolkit.current_user
        name = getattr(user, "name", None) if user else None
        emit_audit_log(
            action="user_logout",
            status="success",
            user_name=name,
            user_id=getattr(user, "id", None) if user else None,
            message="User {} logged out".format(name or "unknown"),
        )
