"""Background malware scanning for API uploads (SI-3).

Scanning inside the request ties the response to clamd: a large archive can
take minutes, past the CDN's 100s origin timeout, so the client sees a 502 even
though the upload succeeded, or clamd's own timeout rejects the file outright.

Uploads through the resource actions of the API are therefore stored first and
scanned by a background job; the resource carries ``scan_status`` (``pending``,
``clean``, ``infected``) so publishers can see the result. Everything else --
the web form, ``package_create``/``package_update`` with inline uploads --
keeps the synchronous ckanext-clamav scan before storage.

On detection the job deletes the stored object and any datastore table built
from it, marks the resource, and alerts; follow-up with the publisher is
manual. Between upload and verdict the new file is served unscanned.
"""

import datetime
import hashlib
import logging

import ckan.model as model
import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit

from . import upload_security as us
from .utils import update_resource_extra

log = logging.getLogger(__name__)

STATUS_FIELD = "scan_status"
SCANNED_AT_FIELD = "scanned_at"
SIGNATURE_FIELD = "scan_signature"

DEFAULT_ASYNC_ACTIONS = "resource_create resource_update resource_patch"
DEFAULT_TIMEOUT = 900


def _async_actions():
    raw = toolkit.config.get(
        "ckanext.sse.upload_scan.async_actions", DEFAULT_ASYNC_ACTIONS)
    return {a for a in raw.replace(",", " ").split() if a}


def _timeout():
    return toolkit.asint(
        toolkit.config.get("ckanext.sse.upload_scan.timeout", DEFAULT_TIMEOUT))


def deferred():
    """Whether the current request's upload is scanned in the background."""
    from flask import has_request_context, request
    if not has_request_context():
        return False
    parts = request.path.strip("/").split("/")
    # /api/action/<name> and /api/<version>/action/<name>
    if len(parts) < 3 or parts[0] != "api" or parts[-2] != "action":
        return False
    return parts[-1] in _async_actions()


class UploadScanPlugin(plugins.SingletonPlugin):
    """Takes ckanext-clamav's place in ``ckan.plugins``: it must come before
    s3filestore so the synchronous scan still runs before storage."""

    plugins.implements(plugins.IUploader, inherit=True)

    def get_resource_uploader(self, data_dict):
        if not data_dict.get("upload") or isinstance(data_dict["upload"], str):
            return None
        if deferred():
            return None
        from ckanext.clamav.utils import scan_file_for_viruses
        scan_file_for_viruses(data_dict)
        return None


# -- hooks ----------------------------------------------------------------------

def before_change(context, resource):
    """Set the scan fields of a new upload in the dict being saved.

    Runs after ``upload_security``'s before-hook, whose stash marks an upload.
    Written together with the file rather than afterwards, so a client that
    reads the resource and writes it back (DataPusher) carries these values
    instead of undoing them. A synchronous scan that fails aborts the save, so
    ``clean`` is only ever stored for a file that passed.
    """
    if not context.get(us._STASH_KEY):
        return
    resource.pop(SIGNATURE_FIELD, None)
    if deferred():
        resource[STATUS_FIELD] = "pending"
        resource.pop(SCANNED_AT_FIELD, None)
    else:
        resource[STATUS_FIELD] = "clean"
        resource[SCANNED_AT_FIELD] = _now()


def after_change(context, resource):
    """Queue a scan for an upload the request stored without scanning.

    Must run before ``upload_security.after_change``, which consumes the stash
    that tells us a file was uploaded.
    """
    digest = context.get(us._STASH_KEY)
    rid = resource.get("id")
    if not (digest and rid and deferred()):
        return
    from rq import Retry
    toolkit.enqueue_job(
        scan_resource, [rid, digest],
        title="Malware scan of resource {}".format(rid),
        rq_kwargs={"timeout": _timeout() + 60, "retry": Retry(max=2)},
    )


# -- job ------------------------------------------------------------------------

class _HashingReader:
    """Hashes what clamd reads, so the verdict is tied to the exact bytes."""

    def __init__(self, body):
        self._body = body
        self.sha256 = hashlib.sha256()

    def read(self, size=-1):
        chunk = self._body.read(size)
        self.sha256.update(chunk)
        return chunk


def _clamd():
    from ckanext.clamav.adapters import CustomClamdNetworkSocket
    from clamd import ClamdUnixSocket
    cfg = toolkit.config
    if cfg.get("ckanext.clamav.socket_type", "unix") == "tcp":
        return CustomClamdNetworkSocket(
            cfg.get("ckanext.clamav.tcp.host"),
            toolkit.asint(cfg.get("ckanext.clamav.tcp.port")),
            _timeout(),
        )
    return ClamdUnixSocket(
        cfg.get("ckanext.clamav.socket_path", "/var/run/clamav/clamd.ctl"),
        _timeout(),
    )


def scan_resource(resource_id, sha256):
    """Scan the stored file of ``resource_id`` that was uploaded as ``sha256``."""
    res = model.Resource.get(resource_id)
    if not res or res.state != "active":
        return "gone"
    if us._stored_hash(res) != sha256:
        # A newer upload replaced this file and queued its own scan.
        return "superseded"

    s3 = us._s3()
    key = us._object_key(s3, res)
    if not key:
        _audit("missing_object", "Uploaded file to scan is not in storage", res)
        return "missing"

    reader = _HashingReader(s3.get_object(Bucket=us._bucket(), Key=key)["Body"])
    result = _clamd().instream(reader)
    status, signature = (result or {}).get("stream", ("ERROR", "no response"))

    if reader.sha256.hexdigest() != sha256:
        # The object changed under us; its own job decides.
        return "superseded"

    if status == "OK":
        update_resource_extra(resource_id, STATUS_FIELD, "clean")
        update_resource_extra(resource_id, SCANNED_AT_FIELD, _now())
        return "clean"
    if status == "FOUND":
        _quarantine(s3, key, res, signature)
        return "infected"
    # Let RQ retry; clamd errors are transient (restart, overload).
    raise RuntimeError("clamd returned {}: {}".format(status, signature))


def _quarantine(s3, key, res, signature):
    s3.delete_object(Bucket=us._bucket(), Key=key)
    if toolkit.asbool((res.extras or {}).get("datastore_active")):
        try:
            toolkit.get_action("datastore_delete")(
                {"ignore_auth": True}, {"resource_id": res.id, "force": True})
        except toolkit.ObjectNotFound:
            pass
    update_resource_extra(res.id, STATUS_FIELD, "infected")
    update_resource_extra(res.id, SIGNATURE_FIELD, signature)
    update_resource_extra(res.id, SCANNED_AT_FIELD, _now())
    _audit("infected", "Malware found in uploaded file; object deleted", res,
           signature=signature, key=key)
    _notify(
        "🚨 Malware found in an upload, file deleted\n"
        "Dataset: {}\nResource: {} ({})\nSignature: {}".format(
            res.package_id, res.name or "", res.id, signature))


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _audit(status, message, res, **extra):
    from .audit import emit_audit_log
    emit_audit_log("malware_scan", status, message,
                   resource_id=res.id, package_id=res.package_id, **extra)


def _notify(text):
    url = (toolkit.config.get("ckanext.sse.upload_scan.gchat_webhook")
           or toolkit.config.get("ckanext.sse.checksum.gchat_webhook"))
    if not url or not url.lower().startswith("https://"):
        return
    try:
        import requests
        requests.post(url, json={"text": text}, timeout=15).raise_for_status()
    except Exception:
        log.exception("Failed to post malware-scan alert to Google Chat")
