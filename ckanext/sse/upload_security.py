"""File-upload security controls (issue #332, SI-3/SI-7).

Two upload-time controls, enforced from ``IResourceController`` before the file
reaches storage:

* a hard file-type allowlist (SI-7) -- anything outside the allowed set is
  rejected, checked on the uploaded filename's extension rather than the
  user-editable ``format`` field;
* a SHA-256 of the uploaded bytes (SI-7 integrity), stamped into resource
  extras so it can be re-verified later.

Malware scanning (SI-3) is ckanext-clamav's own ``IUploader``, configured in
the deployment; it is not implemented here. The maximum resource size is
CKAN-native (``ckan.max_resource_size``) and likewise set in the deployment.

The ``checksums`` CLI backfills the hash for pre-existing resources and
re-verifies stored hashes against the bytes in object storage (SI-7(1)),
reporting drift to the audit trail and, optionally, a Google Chat webhook.
"""

import hashlib
import logging
import os

import ckan.model as model
import ckan.plugins.toolkit as toolkit

from .utils import update_resource_extra

log = logging.getLogger(__name__)

CHECKSUM_FIELD = "sha256"
_STASH_KEY = "_sse_upload_sha256"
_CHUNK = 1024 * 1024

# Real upload formats present in prod (res_format facet, 2026-08); MP4 kept for
# the single existing video resource. Override with the config option.
DEFAULT_ALLOWED_FORMATS = "csv xlsx pdf zip geojson gpkg kml json mp4"


def allowed_formats():
    raw = toolkit.config.get(
        "ckanext.sse.upload.allowed_formats", DEFAULT_ALLOWED_FORMATS
    )
    return {f.strip().lower().lstrip(".") for f in raw.replace(",", " ").split() if f.strip()}


def _upload_stream(upload):
    """The readable, seekable stream behind a CKAN upload, or None.

    CKAN hands us a werkzeug ``FileStorage`` (``.stream``) or a
    ``cgi.FieldStorage`` (``.file``); a plain string means "keep existing file".
    """
    if not upload or isinstance(upload, str):
        return None
    return getattr(upload, "stream", None) or getattr(upload, "file", None)


def _upload_ext(upload):
    name = getattr(upload, "filename", "") or ""
    return os.path.splitext(name)[1].lower().lstrip(".")


def _stream_size(stream):
    pos = stream.tell()
    stream.seek(0, os.SEEK_END)
    size = stream.tell()
    stream.seek(pos)
    return size


def _max_resource_bytes():
    # ckan.max_resource_size is in MB (CKAN-native, set in the deployment).
    mb = toolkit.asint(toolkit.config.get("ckan.max_resource_size", 10))
    return mb * 1024 * 1024


def _enforce_and_hash(context, resource):
    """Reject a disallowed upload; stash the SHA-256 of an allowed one."""
    upload = resource.get("upload")
    stream = _upload_stream(upload)
    if stream is None:
        return  # link/URL resource, or an update that keeps the current file

    # Derive the type from the uploaded filename only -- the format field is
    # user-controlled, so trusting it (even as a fallback) lets an extensionless
    # file named to a disallowed type slip past the allowlist.
    ext = _upload_ext(upload)
    allowed = allowed_formats()
    if not ext or ext not in allowed:
        raise toolkit.ValidationError({
            "upload": [
                "File type '{}' is not allowed. Permitted types: {}.".format(
                    ext or "unknown", ", ".join(sorted(allowed))
                )
            ]
        })

    # Reject oversize here, before clamav scans it: the native max_resource_size
    # is enforced by the uploader, which runs after the scan, so an oversize
    # file would otherwise overrun clamd's stream limit and 500 instead.
    limit = _max_resource_bytes()
    if _stream_size(stream) > limit:
        raise toolkit.ValidationError({
            "upload": ["File is larger than the {} MB limit.".format(limit // (1024 * 1024))]
        })

    h = hashlib.sha256()
    stream.seek(0)
    for chunk in iter(lambda: stream.read(_CHUNK), b""):
        h.update(chunk)
    stream.seek(0)  # rewind so clamav + s3filestore read from the start
    context[_STASH_KEY] = h.hexdigest()


def _persist_hash(context, resource):
    digest = context.pop(_STASH_KEY, None)
    rid = resource.get("id")
    if digest and rid:
        update_resource_extra(rid, CHECKSUM_FIELD, digest)


# -- IResourceController entry points ---------------------------------------

def before_create(context, resource):
    _enforce_and_hash(context, resource)


def before_update(context, current, resource):
    _enforce_and_hash(context, resource)


def after_change(context, resource):
    _persist_hash(context, resource)


# -- object-storage access for the CLI --------------------------------------

def _s3():
    import boto3
    cfg = toolkit.config
    return boto3.client(
        "s3",
        endpoint_url=cfg.get("ckanext.s3filestore.host_name"),
        aws_access_key_id=cfg.get("ckanext.s3filestore.aws_access_key_id"),
        aws_secret_access_key=cfg.get("ckanext.s3filestore.aws_secret_access_key"),
        region_name=cfg.get("ckanext.s3filestore.region_name") or None,
        config=boto3.session.Config(
            signature_version=cfg.get("ckanext.s3filestore.signature_version", "s3v4")
        ),
    )


def _bucket():
    return toolkit.config.get("ckanext.s3filestore.aws_bucket_name")


def _resource_prefix(resource_id):
    storage_path = (toolkit.config.get("ckanext.s3filestore.aws_storage_path") or "").strip("/")
    parts = [p for p in (storage_path, "resources", resource_id) if p]
    return "/".join(parts) + "/"


def _object_key(s3, resource_id):
    """The stored object key for a resource, found by prefix so the filename
    (and any storage-path layout) need not be reconstructed."""
    resp = s3.list_objects_v2(Bucket=_bucket(), Prefix=_resource_prefix(resource_id))
    for obj in resp.get("Contents", []):
        return obj["Key"]
    return None


def _hash_object(s3, key):
    body = s3.get_object(Bucket=_bucket(), Key=key)["Body"]
    h = hashlib.sha256()
    for chunk in iter(lambda: body.read(_CHUNK), b""):
        h.update(chunk)
    return h.hexdigest()


def _upload_resources():
    q = model.Session.query(model.Resource).filter(
        model.Resource.url_type == "upload",
        model.Resource.state == "active",
    )
    return list(q)


def _stored_hash(resource):
    return (resource.extras or {}).get(CHECKSUM_FIELD)


def backfill(dry_run=False):
    """Stamp SHA-256 on active upload resources that lack one."""
    s3 = _s3()
    done, skipped, missing = [], 0, []
    for res in _upload_resources():
        if _stored_hash(res):
            skipped += 1
            continue
        key = _object_key(s3, res.id)
        if not key:
            missing.append(res.id)
            continue
        if not dry_run:
            update_resource_extra(res.id, CHECKSUM_FIELD, _hash_object(s3, key))
        done.append(res.id)
    return {"stamped": done, "already": skipped, "missing_object": missing}


def verify(notify=False):
    """Re-hash stored objects and compare to the recorded SHA-256 (SI-7(1))."""
    s3 = _s3()
    checked, mismatches, missing = 0, [], []
    for res in _upload_resources():
        expected = _stored_hash(res)
        if not expected:
            continue
        key = _object_key(s3, res.id)
        if not key:
            missing.append(res.id)
            continue
        checked += 1
        actual = _hash_object(s3, key)
        if actual != expected:
            mismatches.append({"resource_id": res.id, "expected": expected, "actual": actual})

    report = {"checked": checked, "mismatches": mismatches, "missing_object": missing}
    _report_verify(report, notify)
    return report


def _report_verify(report, notify):
    from .audit import emit_audit_log
    for m in report["mismatches"]:
        emit_audit_log(
            "checksum_verify", "mismatch",
            "Resource file SHA-256 does not match the recorded checksum",
            resource_id=m["resource_id"], expected=m["expected"], actual=m["actual"],
        )
    for rid in report["missing_object"]:
        emit_audit_log(
            "checksum_verify", "missing_object",
            "Resource marked as an upload has no object in storage",
            resource_id=rid,
        )

    failed = report["mismatches"] or report["missing_object"]
    if notify and (failed or _notify_on_success()):
        _notify_gchat(_verify_summary(report))


def _verify_summary(report):
    n_mis, n_missing = len(report["mismatches"]), len(report["missing_object"])
    if not (n_mis or n_missing):
        return "✅ SSE checksum verify: {} resource(s) checked, all match.".format(
            report["checked"])
    lines = ["⚠️ SSE checksum verify FAILED — {} checked".format(report["checked"])]
    if n_mis:
        lines.append("{} checksum mismatch(es): {}".format(
            n_mis, ", ".join(m["resource_id"] for m in report["mismatches"])))
    if n_missing:
        lines.append("{} missing object(s): {}".format(
            n_missing, ", ".join(report["missing_object"])))
    return "\n".join(lines)


def _notify_on_success():
    return toolkit.asbool(
        toolkit.config.get("ckanext.sse.checksum.notify_on_success", False))


def _notify_gchat(text):
    url = toolkit.config.get("ckanext.sse.checksum.gchat_webhook")
    if not url or not url.lower().startswith("https://"):
        return
    try:
        import requests
        requests.post(url, json={"text": text}, timeout=15).raise_for_status()
    except Exception:
        log.exception("Failed to post checksum-verify notification to Google Chat")
