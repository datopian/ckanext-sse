"""Structured security audit logging for authentication and API events.

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

API activity is covered by three further events, none of which CKAN exposes as
a single signal:

* ``api_token_issued`` -- ``IApiToken.postprocess_api_token()`` is the only
  hook handed the token id, and it runs solely inside ``api_token_create``.
  The ``action_succeeded`` signal is no use here: its ``result`` is
  ``{"token": <the raw secret>}`` and carries no id.
* ``api_token_revoked`` -- ``action_succeeded`` filtered to the
  ``api_token_revoke`` sender.
* ``api_request`` -- one event per call to the action API
  (``/api/3/action/<name>``), and nothing else: the rest of the ``/api``
  blueprint is browser plumbing. Emitted from ``request_finished`` rather
  than ``action_succeeded`` because the latter only fires on success, and a
  ``NotAuthorized`` or a token that fails to decode is exactly what an audit
  trail exists to record. The token id comes from
  ``IApiToken.preprocess_api_token()``, which runs once per token-authenticated
  request on the way to the database lookup.

Nothing derived from a request body is logged verbatim. Parameters are
redacted by key name and size-capped before they are serialised -- see
``_audit_params()`` for why both are load-bearing.

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
import hashlib
import ipaddress
import json
import logging
import re
import sys
import time

from flask import g, has_request_context
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

# Request attribute carrying the id of the token this request authenticated
# with. Set by ``preprocess_api_token``, read once the response is ready.
TOKEN_ID_ATTR = "sse_audit_token_id"

# Parameter names whose values must never reach the log, matched
# case-insensitively against the whole key. ``api_token_revoke`` takes the raw
# token as ``token``; the user actions take passwords in several spellings.
# Audit output goes to stdout and from there to a log store with a much wider
# reader set than the database, so a leak here is a real credential
# disclosure. Override with ``ckanext.sse.audit.redacted_params``.
DEFAULT_REDACTED_PARAMS = """
password password1 password2 old_password new_password pass
token api_token apikey api_key key secret client_secret
"""

# Caps on the serialised parameter dict.
#
# These are not tidiness. A log line long enough to be chopped by the
# collector arrives as invalid JSON and takes the whole event with it, so a
# single ``datastore_upsert`` with a large ``records`` list would silently
# destroy its own audit record. Individual values are trimmed first; if the
# dict is still over budget the values are dropped and only the key names
# survive, which is the part that matters for an audit trail anyway.
DEFAULT_MAX_PARAM_VALUE = 512
DEFAULT_MAX_PARAMS = 4096

# Tagging thresholds only -- nothing is rejected, alerting filters on ``flags``.
DEFAULT_SLOW_QUERY_MS = 5000
DEFAULT_LARGE_RESULT_ROWS = 10000


def get_subscriptions():
    return {
        user_logged_in: [on_user_logged_in],
        toolkit.signals.failed_login: [on_failed_login],
        toolkit.signals.request_finished: [on_request_finished],
        toolkit.signals.action_succeeded: [
            {"sender": "api_token_revoke", "receiver": on_api_token_revoked},
        ],
    }


def on_user_logged_in(sender, user=None, **kwargs):
    """flask-login ``user_logged_in``: sender is the app, ``user`` the User."""
    emit_audit_log(
        action="user_login",
        status="success",
        user_name=_safe_attr(user, "name"),
        user_id=_safe_attr(user, "id"),
        message="Successful login for user {}".format(
            _safe_attr(user, "name") or "unknown"
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


def on_api_token_revoked(sender, **kwargs):
    """CKAN ``action_succeeded`` for ``api_token_revoke``.

    ``api_token_revoke`` accepts either a ``jti`` or the raw token, and when
    given the latter it decodes it locally without telling anyone the id it
    arrived at. Decoding it again here would mean handling the secret a second
    time for a field that is nearly always present anyway, so a revocation by
    token value is recorded as such and left without an id.
    """
    data_dict = kwargs.get("data_dict") or {}
    context = kwargs.get("context") or {}
    jti = data_dict.get("jti")
    emit_audit_log(
        action="api_token_revoked",
        status="success",
        user_name=context.get("user"),
        user_id=_safe_attr(context.get("auth_user_obj"), "id"),
        message="API token {} revoked".format(jti or "(identified by value)"),
        token_id=jti,
        revoked_by="jti" if jti else "token_value",
    )


def on_request_finished(sender, response=None, **kwargs):
    """Flask ``request_finished``, re-sent by CKAN, once the response exists.

    Fires for 4xx as well as 2xx, which is the reason for using it in
    preference to ``action_succeeded``: a denied or malformed API call is the
    event most worth having. It does not fire when an exception escapes
    unhandled, so a hard 500 leaves no line -- CKAN's error handlers catch
    almost everything, but not quite everything.

    The whole body is inside the failure boundary, not just the write.
    ``finalize_request`` does not guard its own signal, so anything raised
    here replaces the response CKAN had already built: a 409 validation error
    came back as a 500 until this was in place.
    """
    try:
        _log_api_request(response)
    except Exception:
        log.exception("Failed to emit API request audit log")


def _safe_attr(obj, attr):
    """Read an attribute off a possibly-detached SQLAlchemy instance.

    ``current_user`` is a ``User`` row, and when an action fails CKAN rolls
    the session back before the response is finalised. The instance is then
    detached with its attributes expired, so reading one attempts a refresh
    and raises ``DetachedInstanceError``. Observed on a ``user_update`` that
    failed validation, not a theoretical concern.
    """
    if obj is None:
        return None
    try:
        return getattr(obj, attr, None)
    except Exception:
        return None


def _log_api_request(response):
    if not has_request_context() or not _is_audited_request():
        return

    status_code = getattr(response, "status_code", None)
    token_id = getattr(g, TOKEN_ID_ATTR, None)
    user = toolkit.current_user
    authenticated = not _safe_attr(user, "is_anonymous") if user else False

    if token_id and authenticated:
        token_auth = "token"
    elif token_id:
        # The JWT decoded -- so it was validly signed and unexpired, and
        # ``preprocess_api_token`` saw its id -- but no user came back, which
        # means ``ApiToken.get(jti)`` found no row. The token was revoked or
        # its owner was deleted. Distinguishing this from a live token matters
        # more than any other case here: use of a withdrawn credential is the
        # signal, and it is invisible in the response, which is a perfectly
        # ordinary anonymous 200 on any endpoint that permits anonymous reads.
        token_auth = "token_revoked"
    elif _token_presented():
        # A token arrived but never reached the database lookup, so it failed
        # to decode: expired, signed with another key, or forged.
        token_auth = "token_invalid"
    elif authenticated:
        token_auth = "session"
    else:
        token_auth = "anonymous"

    failed = token_auth in ("token_invalid", "token_revoked") or (
        status_code is not None and status_code >= 400
    )

    api_action = _api_action()
    emit_audit_log(
        action="api_request",
        # An unusable token is an authentication failure even when the
        # endpoint went on to serve the request anonymously with a 200.
        status="failure" if failed else "success",
        user_name=_safe_attr(user, "name") if authenticated else None,
        user_id=_safe_attr(user, "id") if authenticated else None,
        message="API request {} {}".format(
            toolkit.request.method, api_action or toolkit.request.path
        ),
        api_action=api_action,
        http_status=status_code,
        token_id=token_id,
        token_auth=token_auth,
        params=_audit_params(),
    )


def _is_audited_request():
    """Whether this request is a call to the action API.

    Scoped to the action API alone -- ``/api/3/action/<name>`` and the
    unversioned ``/api/action/<name>``. Everything else is out, including the
    rest of the ``/api`` blueprint: the root version document, the autocomplete
    helpers, the template snippet fetcher and the JavaScript translation bundle
    are browser plumbing pulled by every page load, and logging them buries the
    events that matter.

    Detected by the presence of the ``logic_function`` view argument, which is
    what defines an action route, rather than by endpoint or blueprint name.
    Those are not stable: ckanext-googleanalytics re-registers the same two
    URL rules under its own blueprint to count API calls, so on this
    deployment the endpoint is ``google_analytics.action`` and the blueprint is
    ``google_analytics``. Any extension wrapping the action API would shadow
    the name the same way; none of them can drop the view argument without
    breaking the route itself.

    The path check keeps an extension that borrows the same argument name for
    a non-API route from being pulled in.
    """
    if "logic_function" not in (toolkit.request.view_args or {}):
        return False
    return toolkit.request.path.startswith("/api/")


def _api_action():
    """The CKAN action name, taken from the route rather than the body.

    ``/api/3/action/<logic_function>`` binds the name as a view arg, so it is
    already parsed and correct even for requests that failed before the body
    was read.
    """
    view_args = toolkit.request.view_args or {}
    return view_args.get("logic_function") or toolkit.request.endpoint


def _token_presented():
    """Whether the request carried something CKAN would try to read as a token.

    Mirrors ``ckan.views._get_user_for_apitoken`` (2.10): the configured header
    first, then a bare ``Authorization``. A value containing a space is an HTTP
    auth scheme (``Basic``, ``Bearer``, ``Digest``) rather than a token -- CKAN
    applies that rule to only one of its lookups, but the dev portal sits
    behind basic auth, so without applying it here every request there would be
    filed as a failed token attempt.
    """
    header = toolkit.config.get("apikey_header_name", "X-CKAN-API-Key")
    environ = toolkit.request.environ
    candidates = [
        toolkit.request.headers.get(header, ""),
        environ.get(header, ""),
        environ.get("HTTP_AUTHORIZATION", ""),
        environ.get("Authorization", ""),
    ]
    return any(value and " " not in value for value in candidates)


def _audit_params():
    """Everything the caller supplied, redacted and size-capped.

    The union of query string, form and JSON body rather than CKAN's own
    precedence rules: for an audit trail what was *presented* matters, not
    which copy the action happened to read. All three are already parsed and
    cached on the request by the view, so this costs nothing to re-read.
    """
    request = toolkit.request
    raw = {}
    raw.update(request.args.to_dict(flat=True))
    raw.update(request.form.to_dict(flat=True))

    body = request.get_json(silent=True)
    if isinstance(body, dict):
        raw.update(body)

    # File contents are never logged; the field and filename are the audit
    # trail, and the bytes are the resource itself.
    for field, storage in request.files.items():
        raw[field] = "<file:{}>".format(
            getattr(storage, "filename", None) or "unnamed"
        )

    redacted = {
        key: (
            "<redacted>"
            if key.lower() in _redacted_param_names()
            else _trim_value(value)
        )
        for key, value in raw.items()
    }

    max_total = _int_config(
        "ckanext.sse.audit.max_params_bytes", DEFAULT_MAX_PARAMS
    )
    if len(json.dumps(redacted, default=str)) <= max_total:
        return redacted

    # Still over budget after per-value trimming, so keep the shape and lose
    # the content. Which parameters were sent is the part an investigation
    # needs; the values of a bulk upsert are not.
    return {"__truncated__": True, "__keys__": sorted(raw)}


def _trim_value(value):
    """Serialise one parameter value, bounded."""
    if not isinstance(value, (str, int, float, bool, type(None))):
        value = json.dumps(value, default=str)
    if not isinstance(value, str):
        return value

    limit = _int_config(
        "ckanext.sse.audit.max_param_value", DEFAULT_MAX_PARAM_VALUE
    )
    if len(value) <= limit:
        return value
    return value[:limit] + "...<truncated {} chars>".format(len(value) - limit)


def _redacted_param_names():
    configured = toolkit.config.get(
        "ckanext.sse.audit.redacted_params", DEFAULT_REDACTED_PARAMS
    )
    return {
        name.lower()
        for name in re.split(r"[,\s]+", (configured or "").strip())
        if name
    }


def _int_config(key, default):
    """An int setting, normalised so a bad value cannot break a request."""
    try:
        value = toolkit.asint(toolkit.config.get(key, default))
    except (ValueError, TypeError):
        log.warning("Ignoring invalid %s, using %s", key, default)
        return default
    return value if value > 0 else default


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
        "http_method": toolkit.request.method,
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


@toolkit.chained_action
@toolkit.side_effect_free
def datastore_search_sql(original_action, context, data_dict):
    """Record each SQL query: who, how long, how much, and why it failed."""
    started = time.monotonic()
    try:
        result = original_action(context, data_dict)
    except Exception as error:
        _log_sql_query(context, data_dict, started, error=error)
        raise

    _log_sql_query(context, data_dict, started, result=result)
    return result


def _log_sql_query(context, data_dict, started, result=None, error=None):
    try:
        duration_ms = int((time.monotonic() - started) * 1000)
        sql = data_dict.get("sql") or ""
        records = (result or {}).get("records") or []
        truncated = bool((result or {}).get("records_truncated"))

        flags = []
        if duration_ms >= _int_config(
            "ckanext.sse.audit.slow_query_ms", DEFAULT_SLOW_QUERY_MS
        ):
            flags.append("slow")
        if len(records) >= _int_config(
            "ckanext.sse.audit.large_result_rows", DEFAULT_LARGE_RESULT_ROWS
        ):
            flags.append("large")
        if truncated:
            flags.append("truncated")

        emit_audit_log(
            action="datastore_sql_query",
            status="failure" if error else "success",
            user_name=context.get("user") or None,
            user_id=_safe_attr(context.get("auth_user_obj"), "id"),
            message="Datastore SQL query {} in {}ms, {} rows".format(
                "failed" if error else "ran", duration_ms, len(records)
            ),
            token_id=(
                getattr(g, TOKEN_ID_ATTR, None)
                if has_request_context()
                else None
            ),
            sql=_trim_value(sql),
            sql_chars=len(sql),
            # Groups repeats of one query without relying on trimmed text.
            sql_fingerprint=hashlib.sha256(
                " ".join(sql.split()).encode("utf-8")
            ).hexdigest()[:16],
            duration_ms=duration_ms,
            row_count=len(records),
            records_truncated=truncated,
            flags=flags,
            error_class=type(error).__name__ if error else None,
            error_message=_trim_value(str(error)) if error else None,
        )
    except Exception:
        log.exception("Failed to emit datastore SQL audit log")


def emit_audit_log(action, status, message, user_name=None, user_id=None,
                   **extra):
    # A broken audit line must never break the request it describes. These
    # functions run inside signal receivers on the login, logout and request
    # paths, so gathering the context has to be inside the boundary too, not
    # just the write. Failures go to the logger (stderr), where an ERROR
    # severity is accurate.
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
        payload.update(extra)
        payload.update(_request_context())
        # ``default=str`` so an unserialisable parameter value degrades to its
        # repr rather than losing the whole event.
        print(json.dumps(payload, default=str), file=sys.stdout, flush=True)
    except Exception:
        log.exception("Failed to emit security audit log for %s", action)


class SecurityAuditPlugin(plugins.SingletonPlugin):
    """Logs authentication and API events as structured JSON."""

    plugins.implements(plugins.IAuthenticator, inherit=True)
    plugins.implements(plugins.ISignal)
    plugins.implements(plugins.IApiToken, inherit=True)
    plugins.implements(plugins.IActions)

    # ISignal
    def get_signal_subscriptions(self):
        return get_subscriptions()

    # IActions
    def get_actions(self):
        # Chaining onto a missing action raises at startup, and datastore
        # withholds this one unless sqlsearch is enabled.
        if not toolkit.asbool(
            toolkit.config.get("ckan.datastore.sqlsearch.enabled", False)
        ):
            return {}
        return {"datastore_search_sql": datastore_search_sql}

    # IAuthenticator
    def logout(self):
        """Called before the logout runs, so the user is still authenticated.

        Returns None to leave CKAN's logout flow untouched.
        """
        user = toolkit.current_user
        name = _safe_attr(user, "name")
        emit_audit_log(
            action="user_logout",
            status="success",
            user_name=name,
            user_id=_safe_attr(user, "id"),
            message="User {} logged out".format(name or "unknown"),
        )

    # IApiToken
    def preprocess_api_token(self, data):
        """Runs once per token-authenticated request, before the DB lookup.

        The only point on the authentication path where the token id is
        available. Stashed rather than emitted here because the outcome of the
        request is not known yet, and because the same id has to appear on the
        ``api_request`` event for the two to be correlated.

        ``get_user_from_token()`` is also reachable from the CLI, where there
        is no request to attach anything to.
        """
        try:
            if has_request_context() and isinstance(data, dict):
                setattr(g, TOKEN_ID_ATTR, data.get("jti"))
        except Exception:
            log.exception("Failed to record API token id for audit")
        return data

    # IApiToken
    def postprocess_api_token(self, data, jti, data_dict):
        """Runs inside ``api_token_create`` once the token row is committed.

        ``data_dict`` is the validated create payload, so ``user`` is the
        owner of the new token, which is not necessarily whoever asked for it
        -- a sysadmin can mint tokens for other accounts, and that is exactly
        the case worth being able to see. Both are recorded.
        """
        # ``data`` is on its way into the encoder, so this runs on the critical
        # path of minting a token. Nothing here may raise: failing to record an
        # issuance is bad, failing to issue is worse.
        try:
            actor = toolkit.current_user if has_request_context() else None
            emit_audit_log(
                action="api_token_issued",
                status="success",
                user_name=_safe_attr(actor, "name"),
                user_id=_safe_attr(actor, "id"),
                message="API token {} issued for user {}".format(
                    jti, data_dict.get("user", "unknown")
                ),
                token_id=jti,
                token_name=data_dict.get("name"),
                token_owner=data_dict.get("user"),
            )
        except Exception:
            log.exception("Failed to emit API token issuance audit log")
        return data
