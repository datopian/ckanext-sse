"""Tests for ckanext.sse.upload_security (SI-3/SI-7 upload controls).

These exercise the upload-time allowlist and checksum in isolation -- they call
``_enforce_and_hash`` with a synthetic ``FileStorage`` rather than driving a
full ``resource_create``, so they need no database or storage backend.

Run with::

    pytest ckanext/sse/tests/test_upload_security.py
"""

import hashlib
import io

import pytest
from werkzeug.datastructures import FileStorage

from ckan.tests.helpers import changed_config
from ckan.plugins.toolkit import ValidationError

from ckanext.sse import upload_security as us

CSV = b"a,b,c\n1,2,3\n"
CSV_SHA = hashlib.sha256(CSV).hexdigest()


def upload(data=CSV, filename="data.csv"):
    return FileStorage(stream=io.BytesIO(data), filename=filename)


def test_allowed_upload_is_hashed_and_rewound():
    context, resource = {}, {"upload": upload()}
    us._enforce_and_hash(context, resource)
    assert context[us._STASH_KEY] == CSV_SHA
    # stream left at 0 so clamav + s3filestore read the whole file
    assert resource["upload"].stream.read() == CSV


def test_disallowed_extension_is_rejected():
    with pytest.raises(ValidationError):
        us._enforce_and_hash({}, {"upload": upload(filename="evil.exe")})


def test_format_field_cannot_smuggle_a_bad_extension():
    # extension wins over the user-editable format field
    with pytest.raises(ValidationError):
        us._enforce_and_hash(
            {}, {"upload": upload(filename="evil.exe"), "format": "csv"})


def test_extensionless_upload_is_rejected_despite_format():
    # the format field is user-controlled, so it must not satisfy the allowlist
    with pytest.raises(ValidationError):
        us._enforce_and_hash({}, {"upload": upload(filename="data"), "format": "CSV"})


def test_oversize_upload_is_rejected():
    # max_resource_size is MB; a 2-byte file exceeds a 0 MB cap
    with changed_config("ckan.max_resource_size", "0"):
        with pytest.raises(ValidationError):
            us._enforce_and_hash({}, {"upload": upload(b"hi", "note.csv")})


def test_no_upload_is_a_noop():
    context = {}
    us._enforce_and_hash(context, {"url": "http://example.com/x.csv"})
    us._enforce_and_hash(context, {"upload": ""})  # unchanged-file sentinel
    assert us._STASH_KEY not in context


def test_allowlist_is_configurable():
    with changed_config("ckanext.sse.upload.allowed_formats", "txt md"):
        with pytest.raises(ValidationError):
            us._enforce_and_hash({}, {"upload": upload(filename="data.csv")})
        context = {}
        us._enforce_and_hash(context, {"upload": upload(b"hi", "note.txt")})
        assert context[us._STASH_KEY] == hashlib.sha256(b"hi").hexdigest()


def test_persist_hash_writes_extra(monkeypatch):
    calls = []
    monkeypatch.setattr(us, "update_resource_extra",
                        lambda rid, f, v: calls.append((rid, f, v)))
    us._persist_hash({us._STASH_KEY: CSV_SHA}, {"id": "res-1"})
    assert calls == [("res-1", us.CHECKSUM_FIELD, CSV_SHA)]


def test_persist_hash_noop_without_stash(monkeypatch):
    calls = []
    monkeypatch.setattr(us, "update_resource_extra",
                        lambda rid, f, v: calls.append(1))
    us._persist_hash({}, {"id": "res-1"})
    assert calls == []


# -- object selection for backfill/verify -----------------------------------

class FakeS3:
    """In-memory stand-in for the boto3 calls the checksum CLI makes."""

    def __init__(self, objects):
        self.objects = objects  # key -> bytes

    def head_object(self, Bucket, Key):
        from botocore.exceptions import ClientError
        if Key not in self.objects:
            raise ClientError({"Error": {"Code": "404"}}, "HeadObject")
        return {}

    def get_object(self, Bucket, Key):
        return {"Body": io.BytesIO(self.objects[Key])}

    def get_paginator(self, name):
        objects = self.objects

        class Paginator:
            def paginate(self, Bucket, Prefix):
                keys = sorted(k for k in objects if k.startswith(Prefix))
                yield {"Contents": [{"Key": k} for k in keys]}
        return Paginator()


class FakeResource:
    def __init__(self, id, url, sha=None):
        self.id, self.url = id, url
        self.extras = {us.CHECKSUM_FIELD: sha} if sha else {}


OLD, NEW = b"old,data\n", b"new,data\n"
OLD_SHA, NEW_SHA = (hashlib.sha256(b).hexdigest() for b in (OLD, NEW))


@pytest.fixture
def storage(monkeypatch):
    s3 = FakeS3({
        "resources/r1/20260101_data.csv": OLD,
        "resources/r1/20260201_data.csv": NEW,
    })
    monkeypatch.setattr(us, "_s3", lambda: s3)
    monkeypatch.setattr(us, "_bucket", lambda: "bucket")
    writes = []
    monkeypatch.setattr(us, "update_resource_extra",
                        lambda rid, f, v: writes.append((rid, v)))
    monkeypatch.setattr(us, "_report_verify", lambda report, notify: None)
    return s3, writes


def test_object_key_is_the_current_file_not_the_first_listed(storage):
    s3, _ = storage
    res = FakeResource("r1", "20260201_data.csv")
    assert us._object_key(s3, res) == "resources/r1/20260201_data.csv"


def test_object_key_none_when_current_file_absent(storage):
    s3, _ = storage
    assert us._object_key(s3, FakeResource("r1", "gone.csv")) is None


def test_verify_ignores_superseded_objects(storage, monkeypatch):
    res = FakeResource("r1", "20260201_data.csv", NEW_SHA)
    monkeypatch.setattr(us, "_upload_resources", lambda: [res])
    r = us.verify()
    assert r["checked"] == 1 and r["mismatches"] == []


def test_backfill_hashes_the_current_file(storage, monkeypatch):
    _, writes = storage
    monkeypatch.setattr(us, "_upload_resources",
                        lambda: [FakeResource("r1", "20260201_data.csv")])
    us.backfill()
    assert writes == [("r1", NEW_SHA)]


def test_restamp_replaces_hash_taken_from_superseded_file(storage, monkeypatch):
    _, writes = storage
    monkeypatch.setattr(us, "_upload_resources",
                        lambda: [FakeResource("r1", "20260201_data.csv", OLD_SHA)])
    r = us.restamp_stale()
    assert r["restamped"] == ["r1"] and writes == [("r1", NEW_SHA)]


def test_restamp_leaves_unexplained_mismatch(storage, monkeypatch):
    _, writes = storage
    bogus = hashlib.sha256(b"tampered").hexdigest()
    monkeypatch.setattr(us, "_upload_resources",
                        lambda: [FakeResource("r1", "20260201_data.csv", bogus)])
    r = us.restamp_stale()
    assert r["unexplained"] == ["r1"] and writes == []


def test_restamp_dry_run_writes_nothing(storage, monkeypatch):
    _, writes = storage
    monkeypatch.setattr(us, "_upload_resources",
                        lambda: [FakeResource("r1", "20260201_data.csv", OLD_SHA)])
    assert us.restamp_stale(dry_run=True)["restamped"] == ["r1"]
    assert writes == []
