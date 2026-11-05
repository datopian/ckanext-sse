"""Tests for the download and export audit events in ckanext.sse.audit (#362).

The dataset lookup is stubbed, so nothing here creates rows or touches Solr:
the subject is which requests produce an event and what it says.
"""

import json
from types import SimpleNamespace

import pytest
from werkzeug.wrappers import Response

from ckanext.sse import audit

RES_ID = "0c6a1b2e-3f4d-4e5f-8a9b-0c1d2e3f4a5b"
OTHER_ID = "1d7b2c3f-4a5e-4f6a-9b0c-1d2e3f4a5b6c"
SCOPE = {
    "dataset_id": "pkg-id",
    "dataset_name": "substations",
    "organization": "ssen",
    "dataset_private": True,
}


@pytest.fixture
def events(capsys, monkeypatch):
    """Audit events emitted during the test, parsed."""
    monkeypatch.setattr(audit, "_dataset_scope", lambda rid: dict(SCOPE) if rid else {})
    monkeypatch.setattr(audit, "_request_user", lambda: ("alice", "alice-id"))

    def read():
        lines = capsys.readouterr().out.splitlines()
        return [json.loads(line) for line in lines if line.startswith("{")]

    return read


def response(status, location=None):
    resp = Response(status=status)
    if location:
        resp.headers["Location"] = location
    return resp


def finish(app, path, resp):
    with app.flask_app.test_request_context(path):
        audit.on_request_finished(None, response=resp)


plugins = pytest.mark.ckan_config("ckan.plugins", "datastore sse_audit")
usefixtures = pytest.mark.usefixtures("with_plugins")


@plugins
@usefixtures
class TestResourceDownload:
    def test_download_is_recorded_with_dataset(self, app, events):
        finish(
            app,
            "/dataset/substations/resource/{}/download/data.csv".format(RES_ID),
            response(302, "https://bucket.example/data.csv?sig=x"),
        )
        [event] = [e for e in events() if e["action"] == "resource_download"]
        assert event["status"] == "success"
        assert event["user_name"] == "alice"
        assert event["resource_id"] == RES_ID
        assert event["dataset_private"] is True
        assert event["organization"] == "ssen"
        assert event["preview"] is False

    def test_refused_download_is_a_failure(self, app, events):
        finish(
            app,
            "/dataset/substations/resource/{}/download".format(RES_ID),
            response(403),
        )
        [event] = [e for e in events() if e["action"] == "resource_download"]
        assert event["status"] == "failure"
        assert event["http_status"] == 403

    def test_redirect_to_login_is_a_failure(self, app, events):
        finish(
            app,
            "/dataset/substations/resource/{}/download".format(RES_ID),
            response(302, "/user/login?came_from=/dataset/x"),
        )
        [event] = [e for e in events() if e["action"] == "resource_download"]
        assert event["status"] == "failure"

    def test_preview_is_flagged(self, app, events):
        finish(
            app,
            "/dataset/substations/resource/{}/download?preview=1".format(RES_ID),
            response(200),
        )
        [event] = [e for e in events() if e["action"] == "resource_download"]
        assert event["preview"] is True

    def test_resource_page_is_not_a_download(self, app, events):
        finish(app, "/dataset/substations/resource/{}".format(RES_ID), response(200))
        assert not [e for e in events() if e["action"] == "resource_download"]


@plugins
@usefixtures
class TestDatastoreDump:
    def test_dump_is_an_export(self, app, events):
        finish(app, "/datastore/dump/{}?format=json".format(RES_ID), response(200))
        [event] = [e for e in events() if e["action"] == "data_export"]
        assert event["export_method"] == "datastore_dump"
        assert event["resource_ids"] == [RES_ID]
        assert event["format"] == "json"
        assert event["status"] == "success"
        assert event["dataset_name"] == "substations"

    def test_refused_dump_is_a_failure(self, app, events):
        finish(app, "/datastore/dump/{}".format(RES_ID), response(404))
        [event] = [e for e in events() if e["action"] == "data_export"]
        assert event["status"] == "failure"


def search_original(result=None, error=None):
    def original(context, data_dict):
        if error:
            raise error
        return result

    return original


CONTEXT = {"user": "alice", "auth_user_obj": SimpleNamespace(id="alice-id")}


@plugins
@usefixtures
class TestDatastoreSearch:
    def test_search_is_an_export(self, app, events):
        result = {"records": [{"a": 1}, {"a": 2}], "total": 40, "limit": 2}
        with app.flask_app.test_request_context("/api/3/action/datastore_search"):
            out = audit.datastore_search(
                search_original(result), CONTEXT,
                {"resource_id": RES_ID, "limit": 2, "filters": {"a": 1}},
            )
        assert out is result
        [event] = [e for e in events() if e["action"] == "data_export"]
        assert event["export_method"] == "datastore_search"
        assert event["row_count"] == 2
        assert event["total"] == 40
        assert event["user_name"] == "alice"
        assert event["dataset_private"] is True

    def test_failed_search_is_recorded_and_reraised(self, app, events):
        with app.flask_app.test_request_context("/api/3/action/datastore_search"):
            with pytest.raises(ValueError):
                audit.datastore_search(
                    search_original(error=ValueError("nope")), CONTEXT,
                    {"resource_id": RES_ID},
                )
        [event] = [e for e in events() if e["action"] == "data_export"]
        assert event["status"] == "failure"
        assert event["error_class"] == "ValueError"

    def test_search_inside_dump_is_not_recorded(self, app, events):
        with app.flask_app.test_request_context("/datastore/dump/{}".format(RES_ID)):
            audit.datastore_search(
                search_original({"records": []}), CONTEXT, {"resource_id": RES_ID}
            )
        assert not [e for e in events() if e["action"] == "data_export"]

    def test_search_outside_a_request_is_not_recorded(self, events):
        audit.datastore_search(
            search_original({"records": []}), CONTEXT, {"resource_id": RES_ID}
        )
        assert not [e for e in events() if e["action"] == "data_export"]


@plugins
@usefixtures
class TestDatastoreSearchSql:
    def run(self, app, sql, result=None):
        with app.flask_app.test_request_context("/api/3/action/datastore_search_sql"):
            audit.datastore_search_sql(
                search_original(result or {"records": [{"a": 1}]}), CONTEXT, {"sql": sql}
            )

    def test_single_table_carries_dataset(self, app, events):
        self.run(app, 'SELECT * FROM "{}" LIMIT 5'.format(RES_ID.upper()))
        [event] = [e for e in events() if e["action"] == "data_export"]
        assert event["export_method"] == "datastore_search_sql"
        assert event["resource_ids"] == [RES_ID]
        assert event["dataset_name"] == "substations"
        assert event["row_count"] == 1

    def test_join_lists_every_table(self, app, events):
        sql = 'SELECT * FROM "{0}" a JOIN "{1}" b ON a.x = b.x JOIN "{0}" c ON 1=1'.format(
            RES_ID, OTHER_ID
        )
        self.run(app, sql)
        [event] = [e for e in events() if e["action"] == "data_export"]
        assert event["resource_ids"] == sorted([RES_ID, OTHER_ID])
        assert "dataset_name" not in event

    def test_query_event_is_still_emitted(self, app, events):
        self.run(app, 'SELECT 1 FROM "{}"'.format(RES_ID))
        actions = [e["action"] for e in events()]
        assert "datastore_sql_query" in actions
        assert "data_export" in actions


@pytest.mark.ckan_config("ckan.plugins", "datastore sse_audit")
@pytest.mark.usefixtures("clean_db", "clean_index", "with_plugins")
class TestEndToEnd:
    """Real dataset, real DataStore table, real routes."""

    def setup_resource(self):
        from ckan.tests import factories, helpers

        org = factories.Organization(name="ssen-org")
        dataset = factories.Dataset(owner_org=org["id"], private=True)
        resource = factories.Resource(package_id=dataset["id"], url="https://example.com/x.csv")
        helpers.call_action(
            "datastore_create",
            resource_id=resource["id"],
            force=True,
            fields=[{"id": "a", "type": "int"}],
            records=[{"a": i} for i in range(3)],
        )
        sysadmin = factories.Sysadmin()
        return dataset, resource, sysadmin

    def exports(self, capsys, action):
        lines = capsys.readouterr().out.splitlines()
        return [
            e for e in (json.loads(l) for l in lines if l.startswith("{"))
            if e["action"] == action
        ]

    def test_scope_is_read_from_the_model(self):
        dataset, resource, _ = self.setup_resource()
        assert audit._dataset_scope(resource["id"]) == {
            "dataset_id": dataset["id"],
            "dataset_name": dataset["name"],
            "organization": "ssen-org",
            "dataset_private": True,
        }
        assert audit._dataset_scope("no-such-resource") == {}

    def test_api_search_emits_one_export(self, app, capsys):
        dataset, resource, sysadmin = self.setup_resource()
        from ckan.tests import factories
        token = factories.APIToken(user=sysadmin["name"])["token"]
        capsys.readouterr()
        app.get(
            "/api/3/action/datastore_search",
            query_string={"resource_id": resource["id"]},
            headers={"Authorization": token},
        )
        [event] = self.exports(capsys, "data_export")
        assert event["export_method"] == "datastore_search"
        assert event["status"] == "success"
        assert event["user_name"] == sysadmin["name"]
        assert event["row_count"] == 3
        assert event["dataset_name"] == dataset["name"]

    def test_dump_emits_one_export_not_one_per_page(self, app, capsys):
        dataset, resource, sysadmin = self.setup_resource()
        from ckan.tests import factories
        token = factories.APIToken(user=sysadmin["name"])["token"]
        capsys.readouterr()
        resp = app.get(
            "/datastore/dump/{}".format(resource["id"]),
            headers={"Authorization": token},
        )
        assert resp.status_code == 200
        events = self.exports(capsys, "data_export")
        assert [e["export_method"] for e in events] == ["datastore_dump"]
        assert events[0]["user_name"] == sysadmin["name"]
        assert events[0]["dataset_private"] is True

    def test_download_route_emits_event(self, app, capsys):
        dataset, resource, sysadmin = self.setup_resource()
        from ckan.tests import factories
        token = factories.APIToken(user=sysadmin["name"])["token"]
        capsys.readouterr()
        app.get(
            "/dataset/{}/resource/{}/download".format(dataset["id"], resource["id"]),
            headers={"Authorization": token},
            follow_redirects=False,
        )
        [event] = self.exports(capsys, "resource_download")
        assert event["status"] == "success"
        assert event["user_name"] == sysadmin["name"]
        assert event["dataset_name"] == dataset["name"]
