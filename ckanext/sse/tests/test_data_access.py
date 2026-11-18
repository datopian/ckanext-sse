"""Who may read resource data: file routes, DataStore actions and dumps."""

import json

import pytest

import ckan.model as model
import ckan.plugins.toolkit as toolkit
from ckan.tests import factories, helpers

from ckanext.sse import action as sse_action
from ckanext.sse import data_access

pytestmark = [
    pytest.mark.ckan_config("ckan.plugins",
                            "activity datastore scheming_groups sse sse_audit"),
    pytest.mark.ckan_config("scheming.group_schemas", "ckanext.sse:group_schema.yaml"),
    pytest.mark.ckan_config("ckan.datastore.sqlsearch.enabled", "true"),
    pytest.mark.ckan_config("ckan.auth.allow_dataset_collaborators", "true"),
    pytest.mark.usefixtures("sse_tables", "clean_index", "with_plugins", "no_schema",
                            "allowed_domains"),
]

PASSWORD = "Tr0mb0ne-Yak!79-quartz"
ALLOWED = "allowed.example"


@pytest.fixture
def no_schema(monkeypatch):
    monkeypatch.setattr(sse_action, "_get_dataset_schema_frequency_options", lambda: [])


@pytest.fixture
def allowed_domains(monkeypatch):
    monkeypatch.setenv(data_access.ALLOWED_DOMAINS_ENV, "{}, other.example".format(ALLOWED))


def user(**kwargs):
    return factories.User(password=PASSWORD, **kwargs)


def token(user_dict, name="personal"):
    return toolkit.get_action("api_token_create")(
        {"ignore_auth": True, "model": model, "user": user_dict["name"]},
        {"user": user_dict["name"], "name": name},
    )["token"]


def dataset(org, restricted=False, private=False):
    pkg = factories.Dataset(owner_org=org["id"], private=private)
    if restricted:
        helpers.call_action("package_patch", id=pkg["id"],
                            extras=[{"key": "is_restricted", "value": "true"}])
    resource = factories.Resource(package_id=pkg["id"], url="http://example.com/data.csv")
    helpers.call_action(
        "datastore_create", resource_id=resource["id"], force=True,
        fields=[{"id": "name", "type": "text"}], records=[{"name": "row"}],
    )
    return pkg, resource


@pytest.fixture
def world():
    """An organisation, its datasets, and one user of every kind."""
    admin = user()
    member = user()
    editor = user()
    org = factories.Organization(user=admin, users=[
        {"name": member["name"], "capacity": "member"},
        {"name": editor["name"], "capacity": "editor"},
    ])
    users = {
        "org_admin": admin,
        "org_member": member,
        "org_editor": editor,
        "outsider": user(email="someone@gmail.com"),
        "allowed_domain": user(email="analyst@" + ALLOWED),
        "subdomain_lookalike": user(email="analyst@evil" + ALLOWED),
        "collaborator": user(),
        "sysadmin": factories.Sysadmin(password=PASSWORD),
    }
    open_pkg, open_res = dataset(org)
    restricted_pkg, restricted_res = dataset(org, restricted=True)
    private_pkg, private_res = dataset(org, private=True)
    for pkg in (restricted_pkg, private_pkg):
        helpers.call_action("package_collaborator_create", id=pkg["id"],
                            user_id=users["collaborator"]["id"], capacity="member")
    return {
        "users": users,
        "open": (open_pkg, open_res),
        "restricted": (restricted_pkg, restricted_res),
        "private": (private_pkg, private_res),
    }


def headers(world, who, name="personal"):
    if who == "anonymous":
        return {}
    return {"Authorization": token(world["users"][who], name)}


def download_url(pkg, res, suffix="download"):
    return "/dataset/{}/resource/{}/{}".format(pkg["id"], res["id"], suffix)


RESTRICTED_GRANTED = ["org_admin", "org_member", "org_editor", "allowed_domain",
                      "collaborator", "sysadmin"]
RESTRICTED_REFUSED = ["outsider", "subdomain_lookalike"]
SIGNED_IN = RESTRICTED_GRANTED + RESTRICTED_REFUSED


class TestDownloadRoutes:
    @pytest.mark.parametrize("suffix", ["download", "download/data.csv",
                                        "fs_download/data.csv", "derived/parquet", "proxy"])
    @pytest.mark.parametrize("kind", ["open", "restricted", "private"])
    def test_anonymous_is_refused_everywhere(self, app, world, kind, suffix):
        pkg, res = world[kind]
        resp = app.get(download_url(pkg, res, suffix), status=403)
        assert "signed in" in resp.body

    @pytest.mark.parametrize("who", SIGNED_IN)
    def test_open_data_is_served_to_any_signed_in_user(self, app, world, who):
        pkg, res = world["open"]
        resp = app.get(download_url(pkg, res), headers=headers(world, who),
                       follow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers["Location"] == "http://example.com/data.csv"

    @pytest.mark.parametrize("who", RESTRICTED_GRANTED)
    def test_restricted_data_is_served_to_granted_users(self, app, world, who):
        pkg, res = world["restricted"]
        resp = app.get(download_url(pkg, res), headers=headers(world, who),
                       follow_redirects=False)
        assert resp.status_code == 302

    @pytest.mark.parametrize("who", RESTRICTED_REFUSED)
    @pytest.mark.parametrize("suffix", ["download", "download/data.csv",
                                        "fs_download/data.csv", "derived/parquet", "proxy"])
    def test_restricted_data_is_refused_to_others(self, app, world, who, suffix):
        pkg, res = world["restricted"]
        resp = app.get(download_url(pkg, res, suffix), headers=headers(world, who),
                       status=403)
        assert "restricted" in resp.body

    def test_dataset_name_in_url_is_checked_too(self, app, world):
        pkg, res = world["restricted"]
        url = "/dataset/{}/resource/{}/download".format(pkg["name"], res["id"])
        app.get(url, headers=headers(world, "outsider"), status=403)

    def test_other_dataset_in_url_does_not_bypass(self, app, world):
        open_pkg, _ = world["open"]
        _, restricted_res = world["restricted"]
        url = "/dataset/{}/resource/{}/download".format(open_pkg["id"], restricted_res["id"])
        app.get(url, headers=headers(world, "outsider"), status=403)

    @pytest.mark.parametrize("who", ["outsider", "subdomain_lookalike"])
    def test_private_data_is_left_to_ckan(self, app, world, who):
        # The hook lets it through; CKAN's resource_show check in the view refuses.
        pkg, res = world["private"]
        with app.flask_app.test_request_context(download_url(pkg, res)):
            assert data_access.refusal(model.User.get(world["users"][who]["id"]),
                                       model.Package.get(pkg["id"])) is None
        with pytest.raises(toolkit.NotAuthorized):
            helpers.call_action("resource_show",
                                {"user": world["users"][who]["name"], "ignore_auth": False},
                                id=res["id"])

    @pytest.mark.parametrize("who", ["org_member", "collaborator", "sysadmin"])
    def test_private_data_is_served_to_members(self, app, world, who):
        pkg, res = world["private"]
        resp = app.get(download_url(pkg, res), headers=headers(world, who),
                       follow_redirects=False)
        assert resp.status_code == 302

    def test_revoking_a_collaborator_takes_effect_immediately(self, app, world):
        pkg, res = world["restricted"]
        who = world["users"]["collaborator"]
        auth = headers(world, "collaborator")
        app.get(download_url(pkg, res), headers=auth, follow_redirects=False, status=302)
        with app.flask_app.test_request_context():
            helpers.call_action("package_collaborator_delete", id=pkg["id"],
                                user_id=who["id"])
        app.get(download_url(pkg, res), headers=auth, status=403)

    def test_unrestricting_a_dataset_opens_it(self, app, world):
        pkg, res = world["restricted"]
        helpers.call_action("package_patch", id=pkg["id"],
                            extras=[{"key": "is_restricted", "value": "false"}])
        app.get(download_url(pkg, res), headers=headers(world, "outsider"),
                follow_redirects=False, status=302)

    def test_unknown_resource_is_left_to_ckan(self, app, world):
        pkg, _ = world["open"]
        url = "/dataset/{}/resource/{}/download".format(pkg["id"], "no-such-resource")
        with app.flask_app.test_request_context(url):
            assert data_access.enforce_data_routes() is None

    def test_metadata_stays_public(self, app, world):
        pkg, res = world["restricted"]
        app.get("/api/3/action/resource_show?id=" + res["id"], status=200)
        app.get("/api/3/action/package_show?id=" + pkg["id"], status=200)


def api(app, action, payload, auth, status=200):
    return app.post("/api/3/action/" + action, json=payload, headers=auth, status=status)


class TestDataStore:
    @pytest.mark.parametrize("kind", ["open", "restricted", "private"])
    def test_anonymous_cannot_search(self, app, world, kind):
        _, res = world[kind]
        api(app, "datastore_search", {"resource_id": res["id"]}, {}, status=403)

    @pytest.mark.parametrize("who", SIGNED_IN)
    def test_open_data_is_searchable_when_signed_in(self, app, world, who):
        _, res = world["open"]
        resp = api(app, "datastore_search", {"resource_id": res["id"]}, headers(world, who))
        assert resp.json["result"]["records"][0]["name"] == "row"

    @pytest.mark.parametrize("who", RESTRICTED_GRANTED)
    def test_restricted_search_granted(self, app, world, who):
        _, res = world["restricted"]
        api(app, "datastore_search", {"resource_id": res["id"]}, headers(world, who))

    @pytest.mark.parametrize("who", RESTRICTED_REFUSED)
    def test_restricted_search_refused(self, app, world, who):
        _, res = world["restricted"]
        api(app, "datastore_search", {"resource_id": res["id"]}, headers(world, who),
            status=403)

    def test_restricted_search_through_an_alias_is_refused(self, app, world):
        _, res = world["restricted"]
        alias = "alias_" + res["id"].replace("-", "")[:12]
        helpers.call_action("datastore_create", resource_id=res["id"], force=True,
                            aliases=alias)
        api(app, "datastore_search", {"resource_id": alias},
            headers(world, "outsider"), status=403)

    def test_frontend_token_is_checked_like_any_other(self, app, world):
        _, res = world["restricted"]
        api(app, "datastore_search", {"resource_id": res["id"]},
            headers(world, "outsider", "frontend_token"), status=403)
        api(app, "datastore_search", {"resource_id": res["id"]},
            headers(world, "org_member", "frontend_token"))

    def sql(self, *resources):
        tables = ", ".join('"{}"'.format(r["id"]) for r in resources)
        return {"sql": "SELECT * FROM {}".format(tables)}

    def test_sql_anonymous_refused(self, app, world):
        _, res = world["open"]
        api(app, "datastore_search_sql", self.sql(res), {}, status=403)

    @pytest.mark.parametrize("who", RESTRICTED_REFUSED)
    def test_sql_on_restricted_refused(self, app, world, who):
        _, res = world["restricted"]
        api(app, "datastore_search_sql", self.sql(res), headers(world, who), status=403)

    def test_sql_join_with_restricted_table_refused(self, app, world):
        _, open_res = world["open"]
        _, restricted_res = world["restricted"]
        api(app, "datastore_search_sql", self.sql(open_res, restricted_res),
            headers(world, "outsider"), status=403)

    @pytest.mark.parametrize("who", RESTRICTED_GRANTED)
    def test_sql_on_restricted_granted(self, app, world, who):
        _, res = world["restricted"]
        api(app, "datastore_search_sql", self.sql(res), headers(world, who))

    def test_sql_on_open_data_when_signed_in(self, app, world):
        _, res = world["open"]
        api(app, "datastore_search_sql", self.sql(res), headers(world, "outsider"))

    @pytest.mark.parametrize("who", ["org_member", "allowed_domain"])
    def test_dump_of_restricted_data_granted(self, app, world, who):
        _, res = world["restricted"]
        resp = app.get("/datastore/dump/" + res["id"], headers=headers(world, who))
        assert "row" in resp.body

    @pytest.mark.parametrize("who", ["anonymous", "outsider"])
    def test_dump_search_of_restricted_data_refused(self, world, who):
        # The dump view reads through datastore_search with just the user name.
        _, res = world["restricted"]
        name = "" if who == "anonymous" else world["users"][who]["name"]
        with pytest.raises(toolkit.NotAuthorized):
            helpers.call_action("datastore_search", {"user": name, "ignore_auth": False},
                                resource_id=res["id"])

    def test_dump_of_open_data_when_signed_in(self, app, world):
        _, res = world["open"]
        app.get("/datastore/dump/" + res["id"], headers=headers(world, "outsider"), status=200)

    def test_dump_search_of_open_data_refused_when_anonymous(self, world):
        _, res = world["open"]
        with pytest.raises(toolkit.NotAuthorized):
            helpers.call_action("datastore_search", {"user": "", "ignore_auth": False},
                                resource_id=res["id"])

    def test_datastore_info_is_unchanged(self, app, world):
        _, res = world["restricted"]
        api(app, "datastore_info", {"id": res["id"]}, headers(world, "outsider"))

    @pytest.mark.parametrize("kind", ["open", "restricted"])
    @pytest.mark.parametrize("who", ["anonymous", "outsider"])
    def test_datastore_info_lists_fields(self, app, world, kind, who):
        # datastore_info builds its fields from a schema-only datastore_search.
        _, res = world[kind]
        resp = api(app, "datastore_info", {"id": res["id"]}, headers(world, who))
        assert [f["id"] for f in resp.json["result"]["fields"]] == ["name"]

    def test_schema_only_search_is_allowed_anonymously(self, app, world):
        _, res = world["restricted"]
        resp = api(app, "datastore_search",
                    {"resource_id": res["id"], "limit": 0, "include_total": False}, {})
        assert resp.json["result"]["records"] == []

    @pytest.mark.parametrize("payload", [
        {"limit": 0},
        {"limit": 0, "include_total": True},
        {"limit": 0, "include_total": False, "q": "row"},
        {"limit": 0, "include_total": False, "filters": {"name": "row"}},
        {"limit": 1, "include_total": False},
    ])
    @pytest.mark.parametrize("who", ["anonymous", "outsider"])
    def test_searches_that_reveal_data_stay_refused(self, app, world, payload, who):
        _, res = world["restricted"]
        api(app, "datastore_search", dict(payload, resource_id=res["id"]),
            headers(world, who), status=403)


class TestPackageShow:
    @pytest.mark.parametrize("who,expected", [
        ("anonymous", False), ("outsider", False), ("subdomain_lookalike", False),
        ("org_member", True), ("allowed_domain", True), ("collaborator", True),
        ("sysadmin", True),
    ])
    def test_restricted_resources_hidden_unless_granted(self, world, who, expected):
        pkg, _ = world["restricted"]
        name = "" if who == "anonymous" else world["users"][who]["name"]
        result = helpers.call_action("package_show", {"user": name, "ignore_auth": False},
                                     id=pkg["id"])
        assert result["has_access_to_resources"] is expected

    def test_internal_updates_keep_restricted_urls(self, world):
        pkg, res = world["restricted"]
        helpers.call_action("resource_patch", {"ignore_auth": True}, id=res["id"],
                            description="edited by a background job")
        stored = model.Resource.get(res["id"])
        assert stored.url == "http://example.com/data.csv"

    def test_open_dataset_has_access(self, world):
        pkg, _ = world["open"]
        result = helpers.call_action("package_show", {"user": "", "ignore_auth": False},
                                     id=pkg["id"])
        assert result["has_access_to_resources"] is True


class TestFrontendToken:
    def test_frontend_token_may_download(self, app, world):
        pkg, res = world["restricted"]
        app.get(download_url(pkg, res), headers=headers(world, "org_member", "frontend_token"),
                follow_redirects=False, status=302)

    def test_frontend_token_still_needs_access(self, app, world):
        pkg, res = world["restricted"]
        app.get(download_url(pkg, res), headers=headers(world, "outsider", "frontend_token"),
                status=403)

    def test_frontend_token_cannot_post_to_data_routes(self, app, world):
        pkg, res = world["open"]
        app.post(download_url(pkg, res), headers=headers(world, "org_member", "frontend_token"),
                 status=403)

    def test_frontend_token_still_blocked_elsewhere(self, app, world):
        app.get("/dataset/", headers=headers(world, "org_member", "frontend_token"), status=403)


class TestAudit:
    def events(self, capsys):
        lines = capsys.readouterr().out.splitlines()
        return [json.loads(line) for line in lines if line.startswith("{")]

    def test_refused_restricted_download_is_recorded(self, app, world, capsys):
        pkg, res = world["restricted"]
        capsys.readouterr()
        app.get(download_url(pkg, res), headers=headers(world, "outsider"), status=403)
        [event] = [e for e in self.events(capsys) if e["action"] == "resource_download"]
        assert event["status"] == "failure"
        assert event["http_status"] == 403
        assert event["dataset_restricted"] is True
        assert event["user_name"] == world["users"]["outsider"]["name"]

    def test_served_open_download_is_not_restricted(self, app, world, capsys):
        pkg, res = world["open"]
        capsys.readouterr()
        app.get(download_url(pkg, res), headers=headers(world, "outsider"),
                follow_redirects=False, status=302)
        [event] = [e for e in self.events(capsys) if e["action"] == "resource_download"]
        assert event["status"] == "success"
        assert event["dataset_restricted"] is False


class TestPathMatching:
    @pytest.mark.parametrize("path", [
        "/dataset/x/resource/r1/download",
        "/dataset/x/resource/r1/download/file.csv",
        "/dataset/x/resource/r1/fs_download/file.csv",
        "/dataset/x/resource/r1/derived/parquet",
        "/dataset/x/resource/r1/proxy",
        "/en/dataset/x/resource/r1/download",
        "/pt_BR/dataset/x/resource/r1/download/file.csv",
    ])
    def test_data_paths(self, path):
        assert data_access.DATA_PATH.match(path).group(1) == "r1"

    @pytest.mark.parametrize("path", [
        "/dataset/x/resource/r1",
        "/dataset/x/resource/r1/edit",
        "/dataset/x/resource/r1/views",
        "/api/3/action/resource_show",
        "/uploads/group/icon.svg",
        "/dataset/x/resource/r1/downloads",
    ])
    def test_other_paths(self, path):
        assert data_access.DATA_PATH.match(path) is None
