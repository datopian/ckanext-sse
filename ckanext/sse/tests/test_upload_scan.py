"""Tests for ckanext.sse.upload_scan (background SI-3 scanning of API uploads).

Storage, clamd, the job queue and resource extras are faked, so these need no
database, object store or clamd.

Run with::

    pytest ckanext/sse/tests/test_upload_scan.py
"""

import hashlib
import io
from types import SimpleNamespace

import pytest
from werkzeug.datastructures import FileStorage

from ckanext.sse import upload_scan as scan
from ckanext.sse import upload_security as us

DATA = b"PK\x03\x04 pretend zip"
DATA_SHA = hashlib.sha256(DATA).hexdigest()
RID = "res-1"


# -- deferral -------------------------------------------------------------------

@pytest.mark.parametrize("path", [
    "/api/3/action/resource_create",
    "/api/3/action/resource_patch",
    "/api/action/resource_update",
])
def test_resource_actions_are_deferred(test_request_context, path):
    with test_request_context(path, method="POST"):
        assert scan.deferred()


@pytest.mark.parametrize("path", [
    "/api/3/action/package_update",
    "/api/3/action/package_create",
    "/dataset/foo/resource/new",
    "/dataset/foo/resource/abc/edit",
])
def test_other_paths_scan_synchronously(test_request_context, path):
    with test_request_context(path, method="POST"):
        assert not scan.deferred()


def test_no_request_scans_synchronously():
    assert not scan.deferred()


@pytest.mark.ckan_config("ckanext.sse.upload_scan.async_actions", "resource_patch")
def test_async_actions_are_configurable(test_request_context):
    with test_request_context("/api/3/action/resource_create", method="POST"):
        assert not scan.deferred()
    with test_request_context("/api/3/action/resource_patch", method="POST"):
        assert scan.deferred()


# -- uploader -------------------------------------------------------------------

@pytest.fixture
def sync_scans(monkeypatch):
    calls = []
    import ckanext.clamav.utils as clamav_utils
    monkeypatch.setattr(clamav_utils, "scan_file_for_viruses", calls.append)
    return calls


def upload():
    return FileStorage(stream=io.BytesIO(DATA), filename="routes.zip")


def test_uploader_skips_scan_for_api_resource_upload(test_request_context, sync_scans):
    data_dict = {"upload": upload()}
    with test_request_context("/api/3/action/resource_patch", method="POST"):
        assert scan.UploadScanPlugin().get_resource_uploader(data_dict) is None
    assert sync_scans == []


def test_uploader_scans_web_upload_before_storage(test_request_context, sync_scans):
    data_dict = {"upload": upload()}
    with test_request_context("/dataset/foo/resource/new", method="POST"):
        assert scan.UploadScanPlugin().get_resource_uploader(data_dict) is None
    assert sync_scans == [data_dict]


def test_uploader_ignores_requests_without_a_file(sync_scans):
    plugin = scan.UploadScanPlugin()
    assert plugin.get_resource_uploader({}) is None
    assert plugin.get_resource_uploader({"upload": ""}) is None
    assert sync_scans == []


# -- enqueue --------------------------------------------------------------------

@pytest.fixture
def extras(monkeypatch):
    written = {}
    monkeypatch.setattr(
        scan, "update_resource_extra",
        lambda rid, field, value: written.setdefault(rid, {}).__setitem__(field, value))
    return written


@pytest.fixture
def queue(monkeypatch):
    jobs = []
    monkeypatch.setattr(
        scan.toolkit, "enqueue_job",
        lambda fn, args, **kw: jobs.append((fn, args, kw)))
    return jobs


def test_api_upload_is_marked_pending_in_the_saved_dict(test_request_context):
    resource = {"scan_status": "clean", "scanned_at": "earlier",
                "scan_signature": "Old-Sig"}
    with test_request_context("/api/3/action/resource_patch", method="POST"):
        scan.before_change({us._STASH_KEY: DATA_SHA}, resource)
    assert resource["scan_status"] == "pending"
    assert "scanned_at" not in resource and "scan_signature" not in resource


def test_synchronously_scanned_upload_is_marked_clean(test_request_context):
    # the save only happens if the in-request scan passed
    resource = {"scan_status": "infected", "scan_signature": "Old-Sig"}
    with test_request_context("/dataset/foo/resource/new", method="POST"):
        scan.before_change({us._STASH_KEY: DATA_SHA}, resource)
    assert resource["scan_status"] == "clean" and resource["scanned_at"]
    assert "scan_signature" not in resource


def test_metadata_only_update_keeps_scan_fields(test_request_context):
    resource = {"scan_status": "clean", "scanned_at": "earlier"}
    with test_request_context("/api/3/action/resource_patch", method="POST"):
        scan.before_change({}, resource)
    assert resource == {"scan_status": "clean", "scanned_at": "earlier"}


def test_api_upload_is_queued_without_a_separate_write(test_request_context, extras, queue):
    context = {us._STASH_KEY: DATA_SHA}
    with test_request_context("/api/3/action/resource_patch", method="POST"):
        scan.after_change(context, {"id": RID})
    assert extras == {}
    (fn, args, kw), = queue
    assert fn is scan.scan_resource and args == [RID, DATA_SHA]
    assert kw["rq_kwargs"]["timeout"] > scan.DEFAULT_TIMEOUT
    # the stash is left for upload_security to persist the checksum
    assert context[us._STASH_KEY] == DATA_SHA


def test_metadata_only_patch_queues_nothing(test_request_context, extras, queue):
    with test_request_context("/api/3/action/resource_patch", method="POST"):
        scan.after_change({}, {"id": RID})
    assert extras == {} and queue == []


def test_web_upload_queues_nothing(test_request_context, extras, queue):
    with test_request_context("/dataset/foo/resource/new", method="POST"):
        scan.after_change({us._STASH_KEY: DATA_SHA}, {"id": RID})
    assert extras == {} and queue == []


# -- job ------------------------------------------------------------------------

class FakeS3:
    def __init__(self, data=DATA):
        self.data, self.deleted = data, []

    def get_object(self, Bucket, Key):
        return {"Body": io.BytesIO(self.data)}

    def delete_object(self, Bucket, Key):
        self.deleted.append(Key)


class FakeClamd:
    def __init__(self, status, signature=None):
        self.result, self.read = ("stream", (status, signature)), b""

    def instream(self, buff):
        for chunk in iter(lambda: buff.read(4), b""):
            self.read += chunk
        return dict([self.result])


@pytest.fixture
def stored(monkeypatch, extras):
    """A resource whose current file is DATA, with storage and clamd faked."""
    res = SimpleNamespace(id=RID, package_id="pkg-1", name="HV Route", state="active",
                          extras={us.CHECKSUM_FIELD: DATA_SHA})
    s3 = FakeS3()
    env = SimpleNamespace(res=res, s3=s3, clamd=FakeClamd("OK"), alerts=[], audits=[],
                          datastore_deletes=[])
    monkeypatch.setattr(scan.model.Resource, "get", staticmethod(lambda rid: res))
    monkeypatch.setattr(us, "_s3", lambda: s3)
    monkeypatch.setattr(us, "_bucket", lambda: "bucket")
    monkeypatch.setattr(us, "_object_key", lambda s3, r: "resources/res-1/routes.zip")
    monkeypatch.setattr(scan, "_clamd", lambda: env.clamd)
    monkeypatch.setattr(scan, "_notify", env.alerts.append)
    monkeypatch.setattr(scan, "_audit", lambda status, msg, r, **kw: env.audits.append(status))

    def get_action(name):
        assert name == "datastore_delete"
        return lambda ctx, data: env.datastore_deletes.append(data["resource_id"])
    monkeypatch.setattr(scan.toolkit, "get_action", get_action)
    return env


def test_clean_file_is_marked_clean(stored, extras):
    assert scan.scan_resource(RID, DATA_SHA) == "clean"
    assert stored.clamd.read == DATA
    assert extras[RID]["scan_status"] == "clean" and "scanned_at" in extras[RID]
    assert stored.s3.deleted == [] and stored.alerts == []


def test_infected_file_is_deleted_marked_and_alerted(stored, extras):
    stored.clamd = FakeClamd("FOUND", "Eicar-Signature")
    assert scan.scan_resource(RID, DATA_SHA) == "infected"
    assert stored.s3.deleted == ["resources/res-1/routes.zip"]
    assert extras[RID]["scan_status"] == "infected"
    assert extras[RID]["scan_signature"] == "Eicar-Signature"
    assert stored.audits == ["infected"]
    assert len(stored.alerts) == 1 and "Eicar-Signature" in stored.alerts[0]
    assert stored.datastore_deletes == []


def test_infected_file_also_drops_its_datastore_table(stored):
    stored.res.extras["datastore_active"] = True
    stored.clamd = FakeClamd("FOUND", "Eicar-Signature")
    scan.scan_resource(RID, DATA_SHA)
    assert stored.datastore_deletes == [RID]


def test_superseded_upload_is_not_scanned(stored, extras):
    stored.res.extras[us.CHECKSUM_FIELD] = "newer-upload"
    assert scan.scan_resource(RID, DATA_SHA) == "superseded"
    assert stored.clamd.read == b"" and extras == {}


def test_object_replaced_mid_scan_takes_no_action(stored, extras):
    # The bytes clamd saw are not the upload this job was queued for, so even
    # a detection must not delete what is now the resource's file.
    stored.s3.data = b"a different file"
    stored.clamd = FakeClamd("FOUND", "Eicar-Signature")
    assert scan.scan_resource(RID, DATA_SHA) == "superseded"
    assert stored.s3.deleted == [] and extras == {}


def test_missing_object_is_audited(stored, monkeypatch):
    monkeypatch.setattr(us, "_object_key", lambda s3, r: None)
    assert scan.scan_resource(RID, DATA_SHA) == "missing"
    assert stored.audits == ["missing_object"]


def test_deleted_resource_is_skipped(stored):
    stored.res.state = "deleted"
    assert scan.scan_resource(RID, DATA_SHA) == "gone"


def test_clamd_error_raises_for_retry(stored, extras):
    stored.clamd = FakeClamd("ERROR", "INSTREAM size limit exceeded")
    with pytest.raises(RuntimeError):
        scan.scan_resource(RID, DATA_SHA)
    assert extras == {} and stored.s3.deleted == []
