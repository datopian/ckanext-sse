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

Recovering the client address takes two different routes depending on the
environment, both measured rather than assumed:

* Without a CDN (ckan-dev.sse.datopian.com) ingress-nginx replaces
  ``X-Forwarded-For`` with the address it observed, so the chain arrives with a
  single trustworthy entry and that entry is the client.
* Behind Cloudflare (ckan-prod.sse.datopian.com) the address nginx observes is
  a Cloudflare edge, and because nginx discards the incoming header,
  Cloudflare's own ``X-Forwarded-For`` -- the one carrying the real client -- is
  thrown away before CKAN sees it. Hop counting cannot recover it; there is
  nothing left in the chain to count to. ``CF-Connecting-IP`` survives, and is
  honoured only when the address nginx observed is itself inside Cloudflare's
  published ranges, so a request reaching the origin directly cannot forge it.
"""

import datetime
import ipaddress
import json
import logging
import re
import sys

from flask import has_request_context
from flask_login import user_logged_in

import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit

log = logging.getLogger(__name__)

EVENT_TYPE = "security_audit"

# Number of trusted proxies sitting *in front of* the one that terminates the
# connection to CKAN.
#
# ingress-nginx writes the peer address it observed into X-Forwarded-For: it
# replaces the header by default, and with ``compute-full-forwarded-for`` it
# appends that address after any client-supplied chain. Either way the
# *rightmost* entry is the only one written by something we trust, so hop 0 --
# the rightmost -- is the client. Everything further left is client-supplied
# and therefore spoofable.
#
# Raise this only when additional trusted proxies sit in front of the ingress
# (a CDN, for instance); each one shifts the real client one place further
# left. Measured against ckan-dev.sse.datopian.com: the chain arrives with a
# single entry, so 0 is correct there.
#
# Note this cannot recover the client from behind a CDN that nginx does not
# trust -- see CF-Connecting-IP handling below.
DEFAULT_TRUSTED_PROXIES = 0

# Header a trusted CDN uses to carry the original client address. Set to an
# empty value to disable the lookup entirely.
DEFAULT_CLIENT_IP_HEADER = "CF-Connecting-IP"

# Cloudflare's published edge ranges, from https://www.cloudflare.com/ips-v4
# and ips-v6 (retrieved 2026-07-29). CF-Connecting-IP is honoured only when the
# address nginx observed falls inside one of these, so an attacker reaching the
# origin directly cannot dictate the client address by setting the header.
# Override with ``ckanext.sse.audit.cdn_cidrs`` when these change.
DEFAULT_CDN_CIDRS = """
173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22
141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20
197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13
104.24.0.0/14 172.64.0.0/13 131.0.72.0/22
2400:cb00::/32 2606:4700::/32 2803:f800::/32 2405:b500::/32
2405:8100::/32 2a06:98c0::/29 2c0f:f248::/32
"""


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
    cdn_client_ip = environ.get(_client_ip_header_key())

    return {
        "source_ip": _client_ip(forwarded_for, remote_addr, cdn_client_ip),
        "forwarded_for": forwarded_for,
        "remote_addr": remote_addr,
        # What the trusted proxy says it saw connect, and the CDN's claim about
        # the original client. Both kept so a wrong trust decision stays
        # auditable after the fact.
        "observed_peer": _observed_peer(forwarded_for, remote_addr),
        "cdn_client_ip": cdn_client_ip,
        "user_agent": environ.get("HTTP_USER_AGENT"),
        "request_path": toolkit.request.path,
    }


def _client_ip_header_key():
    """WSGI environ key for the configured CDN client-address header."""
    name = toolkit.config.get(
        "ckanext.sse.audit.client_ip_header", DEFAULT_CLIENT_IP_HEADER
    )
    if not name:
        return ""
    return "HTTP_" + name.strip().upper().replace("-", "_")


def _observed_peer(forwarded_for, remote_addr):
    """The address our trusted proxy reports as having connected to it.

    ingress-nginx writes this as the rightmost X-Forwarded-For entry, so it is
    an attestation rather than a client claim. Outside a trusted peer there is
    nothing to attest and the connecting address is all we have.
    """
    if not _peer_is_trusted(remote_addr):
        return remote_addr
    chain = _forwarded_chain(forwarded_for)
    return chain[-1] if chain else remote_addr


def _forwarded_chain(forwarded_for):
    if not forwarded_for:
        return []
    return [part.strip() for part in forwarded_for.split(",") if part.strip()]


def _in_cdn_range(address):
    """Whether ``address`` is a published CDN edge, i.e. may set the header."""
    if not address:
        return False
    try:
        addr = ipaddress.ip_address(address)
    except ValueError:
        return False
    addr = getattr(addr, "ipv4_mapped", None) or addr

    configured = toolkit.config.get("ckanext.sse.audit.cdn_cidrs", DEFAULT_CDN_CIDRS)
    for entry in re.split(r"[,\s]+", (configured or "").strip()):
        if not entry:
            continue
        try:
            if addr in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            log.warning(
                "Ignoring invalid ckanext.sse.audit.cdn_cidrs entry %r", entry
            )
    return False


def _trusted_proxy_count():
    """``trusted_proxies``, normalised so a bad value cannot break a login."""
    raw = toolkit.config.get(
        "ckanext.sse.audit.trusted_proxies", DEFAULT_TRUSTED_PROXIES
    )
    try:
        count = toolkit.asint(raw)
    except (ValueError, TypeError):
        log.warning(
            "Ignoring invalid ckanext.sse.audit.trusted_proxies %r, using %s",
            raw,
            DEFAULT_TRUSTED_PROXIES,
        )
        return DEFAULT_TRUSTED_PROXIES
    # A negative count would index past the end of the chain.
    return max(0, count)


def _peer_is_trusted(remote_addr):
    """Whether the host that opened this connection may dictate the chain.

    Without this check any client could set ``source_ip`` to whatever it liked
    simply by sending an ``X-Forwarded-For`` header.
    """
    if not remote_addr:
        return False

    try:
        peer = ipaddress.ip_address(remote_addr)
    except ValueError:
        return False

    # CKAN sees the ingress as an IPv4-mapped IPv6 address (::ffff:10.60.1.7).
    peer = getattr(peer, "ipv4_mapped", None) or peer

    configured = toolkit.config.get("ckanext.sse.audit.trusted_proxy_cidrs", "")
    if not configured:
        # No allowlist set: trust only private/loopback peers, which is what an
        # in-cluster ingress looks like. This stops spoofing from the internet
        # but not from inside the cluster -- narrow the setting to the ingress
        # pod range in deployment to close that too.
        return peer.is_private or peer.is_loopback

    for entry in re.split(r"[,\s]+", configured.strip()):
        if not entry:
            continue
        try:
            if peer in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            log.warning(
                "Ignoring invalid ckanext.sse.audit.trusted_proxy_cidrs entry %r",
                entry,
            )
    return False


def _client_ip(forwarded_for, remote_addr, cdn_client_ip=None):
    """Resolve the client address.

    Falls back to the connecting peer whenever nothing more trustworthy is
    available. Every input is logged alongside the result, so a wrong trust
    decision loses no information and can be recomputed later.
    """
    if not forwarded_for or not _peer_is_trusted(remote_addr):
        return remote_addr

    chain = _forwarded_chain(forwarded_for)
    if not chain:
        return remote_addr

    # The rightmost entry is the one our trusted proxy wrote, so it says who
    # actually connected to it. If that was a CDN edge, the CDN's header is the
    # only remaining record of the original client -- nginx discarded the
    # forwarded chain the CDN sent.
    if cdn_client_ip and _in_cdn_range(chain[-1]):
        candidate = cdn_client_ip.split(",")[0].strip()
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            log.warning("Ignoring malformed CDN client address %r", cdn_client_ip)
        else:
            return candidate

    # Count in from the right. Clamps to the leftmost entry if the chain is
    # shorter than the configured hop count.
    index = max(0, len(chain) - 1 - _trusted_proxy_count())
    return chain[index]


def emit_audit_log(action, status, message, user_name=None, user_id=None):
    # A broken audit line must never break the request it describes. These
    # functions run inside signal receivers on the login and logout paths, so
    # gathering the context has to be inside the boundary too, not just the
    # write. Failures go to the logger (stderr), where an ERROR severity is
    # accurate.
    try:
        payload = {
            "event_type": EVENT_TYPE,
            # Event time, not ingestion time -- the collector's own clock can
            # lag behind under load, and there is no log formatter supplying
            # one here.
            "timestamp": datetime.datetime.now(
                datetime.timezone.utc
            ).isoformat(),
            "action": action,
            "status": status,
            "user_name": user_name or "anonymous",
            "user_id": user_id,
            "message": message,
        }
        payload.update(_request_context())
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
