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


def test_extensionless_upload_falls_back_to_format():
    context = {}
    us._enforce_and_hash(context, {"upload": upload(filename="data"), "format": "CSV"})
    assert context[us._STASH_KEY] == CSV_SHA


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
