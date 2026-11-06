"""File history of a resource, read from the dataset's activity snapshots."""

import pytest

from ckan.tests import factories, helpers

from ckanext.sse import action as sse_action
from ckanext.sse import file_history
from ckanext.sse.utils import update_resource_extra

pytestmark = [
    pytest.mark.ckan_config("ckan.plugins", "activity datastore sse"),
    pytest.mark.ckan_config("ckan.datastore.sqlsearch.enabled", "true"),
    pytest.mark.usefixtures("sse_tables", "clean_index", "with_plugins", "no_schema"),
]


@pytest.fixture
def no_schema(monkeypatch):
    monkeypatch.setattr(sse_action, "_get_dataset_schema_frequency_options", lambda: [])


def replace(user, resource_id, filename, sha256=None):
    data = {"id": resource_id, "url": filename, "url_type": "upload"}
    if sha256 is not None:
        data["sha256"] = sha256
    helpers.call_action("resource_patch", {"user": user["name"]}, **data)


def test_each_file_is_listed_once_newest_first_with_its_checksum():
    user = factories.Sysadmin(password="Tr0mb0ne-Yak!79-quartz")
    dataset = factories.Dataset(user=user)
    resource = factories.Resource(
        package_id=dataset["id"], url="data.csv", url_type="upload",
        sha256="aaa", user=user,
    )
    replace(user, resource["id"], "data-20261106-111618.csv", "bbb")
    helpers.call_action(
        "resource_patch", {"user": user["name"]}, id=resource["id"], name="renamed")

    history = file_history.resource_file_history(dataset["id"], resource["id"])

    assert [(f["filename"], f["sha256"], f["current"]) for f in history] == [
        ("data-20261106-111618.csv", "bbb", True),
        ("data.csv", "aaa", False),
    ]
    assert history[0]["uploaded_by"] == user["name"]
    assert history[0]["url"].endswith("/download/data-20261106-111618.csv")
    assert history[1]["uploaded_at"] < history[0]["uploaded_at"]


def test_a_checksum_written_after_the_save_reaches_the_history():
    user = factories.Sysadmin(password="Tr0mb0ne-Yak!79-quartz")
    dataset = factories.Dataset(user=user)
    resource = factories.Resource(
        package_id=dataset["id"], url="data.csv", url_type="upload",
        sha256="aaa", user=user,
    )
    # A direct upload is saved with its checksum pending...
    replace(user, resource["id"], "new.csv", "")
    assert file_history.resource_file_history(dataset["id"], resource["id"])[0]["sha256"] == ""

    # ...and the scan job writes it later, outside any action.
    update_resource_extra(resource["id"], "sha256", "ccc")
    file_history.record_checksum_activity(dataset["id"])

    newest = file_history.resource_file_history(dataset["id"], resource["id"])[0]
    assert (newest["filename"], newest["sha256"]) == ("new.csv", "ccc")


def test_private_datasets_get_no_extra_activity():
    user = factories.Sysadmin(password="Tr0mb0ne-Yak!79-quartz")
    org = factories.Organization()
    dataset = factories.Dataset(owner_org=org["id"], private=True)
    assert file_history.record_checksum_activity(dataset["id"]) is None
