"""Personal dashboards: access rules and config validation."""

import copy

import pytest

from ckan import logic, model
from ckan.tests import factories, helpers

from ckanext.sse import action as sse_action
from ckanext.sse.model import Dashboard

pytestmark = [
    pytest.mark.ckan_config("ckan.plugins", "activity datastore sse"),
    pytest.mark.usefixtures("sse_tables", "clean_index", "with_plugins", "no_schema"),
]

PASSWORD = "Tr0mb0ne-Yak!79-quartz"


@pytest.fixture
def no_schema(monkeypatch):
    monkeypatch.setattr(sse_action, "_get_dataset_schema_frequency_options", lambda: [])


def call(name, user=None, **data):
    """Run an action with auth enforced, as the portal's API calls are."""
    context = {"ignore_auth": False, "user": user["name"] if user else ""}
    return helpers.call_action(name, context, **data)


def datastore_resource(owner, private=False, restricted=False):
    dataset = factories.Dataset(user=owner, private=private,
                                owner_org=factories.Organization(user=owner)["id"])
    if restricted:
        # Scheming keeps is_restricted as a package extra.
        helpers.call_action("package_patch", {"user": owner["name"]}, id=dataset["id"],
                            extras=[{"key": "is_restricted", "value": "true"}])
    resource = factories.Resource(package_id=dataset["id"], name="dispatch",
                                  url="http://example.com/dispatch.csv")
    result = helpers.call_action(
        "datastore_create",
        resource_id=resource["id"],
        fields=[
            {"id": "status", "type": "text"},
            {"id": "mw", "type": "numeric"},
            {"id": "dispatched_at", "type": "timestamp"},
            {"id": "lat", "type": "numeric"},
            {"id": "lon", "type": "numeric"},
        ],
        records=[{"status": "Active", "mw": 1.5, "dispatched_at": "2026-11-01",
                  "lat": 57.1, "lon": -2.1}],
        force=True,
    )
    return result["resource_id"]


def config_for(resource_id):
    return {
        "schema_version": 1,
        "filters": [
            {"id": "status", "label": "Status", "type": "value",
             "default_option": "all",
             "options": [{"id": "all", "label": "All", "all": True},
                         {"id": "active", "label": "Active", "value": "Active"}]},
            {"id": "period", "label": "Period", "type": "relative_date",
             "default_option": "d30",
             "options": [{"id": "d30", "label": "Last 30 days", "window": "last_30_days"}]},
        ],
        "rows": [
            {"id": "r1", "columns": 2, "cells": [
                {"id": "kpi", "type": "kpi", "resource_id": resource_id,
                 "label": "Total MW", "query": {"measure": "mw", "aggregate": "SUM"},
                 "style": {"kind": "number"},
                 "filter_bindings": {"status": "status", "period": "dispatched_at"}},
                {"id": "note", "type": "text", "markdown": "**Total** dispatched."},
            ]},
            {"id": "r2", "columns": 1, "cells": [
                {"id": "chart", "type": "chart", "resource_id": resource_id,
                 "query": {"dimension": "status", "measure": "mw", "aggregate": "SUM",
                           "filters": [{"column": "mw", "operation": ">", "value": "0"}]},
                 "chart": {"chartType": "bar_stacked", "sorting": {"by": "data", "order": "DESC"}},
                 "filter_bindings": {"status": "status"}},
            ]},
            {"id": "r3", "columns": 2, "cells": [
                {"id": "map", "type": "map", "layers": [
                    {"id": "points", "kind": "points", "resource_id": resource_id,
                     "lat": "lat", "lon": "lon", "tooltip": ["status"]}]},
                None,
            ]},
        ],
    }


@pytest.fixture
def user():
    return factories.User(password=PASSWORD)


@pytest.fixture
def resource_id():
    return datastore_resource(factories.Sysadmin(password=PASSWORD))


def test_owner_can_create_show_list_update_and_delete(user, resource_id):
    created = call("sse_dashboard_create", user, title="Dispatch",
                   config=config_for(resource_id))

    assert created["owner_user_id"] == user["id"]
    assert created["visibility"] == "private"
    assert call("sse_dashboard_show", user, id=created["id"])["config"]["rows"][0]["id"] == "r1"

    listed = call("sse_dashboard_list", user)
    assert [d["id"] for d in listed] == [created["id"]]
    assert "config" not in listed[0]
    assert listed[0]["layout"] == [["kpi", "text"], ["chart"]]

    updated = call("sse_dashboard_update", user, id=created["id"], title="Renamed")
    assert updated["title"] == "Renamed"
    assert updated["config"] == created["config"]

    call("sse_dashboard_delete", user, id=created["id"])
    assert Dashboard.get(created["id"]) is None


def test_config_can_be_sent_as_json(user, resource_id):
    import json
    created = call("sse_dashboard_create", user, title="JSON",
                   config=json.dumps(config_for(resource_id)))
    assert created["config"]["schema_version"] == 1


def test_anonymous_users_cannot_use_dashboards(resource_id):
    with pytest.raises(logic.NotAuthorized):
        call("sse_dashboard_create", None, title="x", config=config_for(resource_id))
    with pytest.raises(logic.NotAuthorized):
        call("sse_dashboard_list", None)


def test_dashboards_are_visible_to_their_owner_only(user, resource_id):
    other = factories.User(password=PASSWORD)
    dashboard = call("sse_dashboard_create", user, title="Mine",
                     config=config_for(resource_id))

    for name in ("sse_dashboard_show", "sse_dashboard_delete"):
        with pytest.raises(logic.NotAuthorized):
            call(name, other, id=dashboard["id"])
    with pytest.raises(logic.NotAuthorized):
        call("sse_dashboard_update", other, id=dashboard["id"], title="Theirs")
    with pytest.raises(logic.NotAuthorized):
        call("sse_dashboard_list", other, user_id=user["id"])
    assert call("sse_dashboard_list", other) == []


def test_sysadmins_can_read_dashboards_for_support(user, resource_id):
    dashboard = call("sse_dashboard_create", user, title="Mine",
                     config=config_for(resource_id))
    admin = factories.Sysadmin(password=PASSWORD)

    assert call("sse_dashboard_show", admin, id=dashboard["id"])["id"] == dashboard["id"]
    assert [d["id"] for d in call("sse_dashboard_list", admin, user_id=user["id"])] == [dashboard["id"]]


def test_unknown_dashboard_is_not_found(user):
    with pytest.raises(logic.NotFound):
        call("sse_dashboard_show", user, id="missing")


def _errors(user, config):
    with pytest.raises(logic.ValidationError) as exc:
        call("sse_dashboard_create", user, title="Bad", config=config)
    return " | ".join(exc.value.error_dict["config"])


@pytest.mark.parametrize("private,restricted", [(True, False), (False, True)])
def test_data_not_open_to_every_signed_in_user_is_rejected(user, private, restricted):
    resource_id = datastore_resource(
        factories.Sysadmin(password=PASSWORD), private=private, restricted=restricted)

    assert "not available to every signed-in user" in _errors(user, config_for(resource_id))


def test_resources_without_datastore_tables_are_rejected_for_charts(user):
    owner = factories.Sysadmin(password=PASSWORD)
    resource = factories.Resource(package_id=factories.Dataset(user=owner)["id"],
                                  url="http://example.com/file.zip")
    config = config_for(resource["id"])

    assert "no tabular data in the DataStore" in _errors(user, config)


def test_widget_rules_are_enforced(user, resource_id):
    config = config_for(resource_id)
    chart = config["rows"][1]["cells"][0]
    chart["query"]["measure"] = "missing"
    chart["chart"]["chartType"] = "radar"
    chart["query"]["filters"][0]["operation"] = "LIKE"
    config["rows"][0]["cells"][0]["filter_bindings"]["period"] = "status"
    config["rows"][0]["cells"][1]["markdown"] = "x" * 5001
    config["rows"][2] = {"id": "r3", "columns": 3, "cells": [
        copy.deepcopy(config["rows"][2]["cells"][0]), None, None]}

    errors = _errors(user, config)

    assert "unknown column 'missing'" in errors
    assert "chartType: must be one of" in errors
    assert "operation: must be one of" in errors
    assert "relative date filters need a date or timestamp column" in errors
    assert "markdown: is required, up to 5000 characters" in errors
    assert "maps can only be placed in 1 or 2 column rows" in errors


def test_structure_rules_are_enforced(user, resource_id):
    config = config_for(resource_id)
    config["schema_version"] = 2
    config["filters"][0]["default_option"] = "nope"
    config["rows"][1]["cells"][0]["id"] = "kpi"
    config["rows"][1]["cells"][0]["filter_bindings"] = {"unknown": "status"}
    config["rows"][2]["cells"] = [None]

    errors = _errors(user, config)

    assert "schema_version: must be 1" in errors
    assert "default_option: must be one of the filter's option ids" in errors
    assert "duplicate id 'kpi'" in errors
    assert "unknown dashboard filter" in errors
    assert "rows[2].cells: must have one entry per column" in errors


def test_kpi_styles_need_their_reference_values(user, resource_id):
    config = config_for(resource_id)
    kpi = config["rows"][0]["cells"][0]
    kpi["style"] = {"kind": "gauge", "min": 0}
    errors = _errors(user, config)
    assert "a gauge needs a minimum and maximum, or a target" in errors

    kpi["style"] = {"kind": "change"}
    assert "style.reference: is required" in _errors(user, config)


def test_title_is_required(user, resource_id):
    with pytest.raises(logic.ValidationError) as exc:
        call("sse_dashboard_create", user, title="  ", config=config_for(resource_id))
    assert "title" in exc.value.error_dict


def test_dashboards_survive_the_account_being_deleted(user, resource_id):
    dashboard = call("sse_dashboard_create", user, title="Kept",
                     config=config_for(resource_id))
    helpers.call_action("user_delete", id=user["id"])
    model.Session.remove()

    assert Dashboard.get(dashboard["id"]) is not None


def test_chart_date_group_is_checked(user, resource_id):
    config = config_for(resource_id)
    chart = config["rows"][1]["cells"][0]
    chart["query"]["date_group"] = "fortnight"
    with pytest.raises(tk.ValidationError) as e:
        call("sse_dashboard_create", user, title="Bad period", config=config)
    assert "fortnight" not in str(e.value) and "date_group" in str(e.value)

    chart["query"]["date_group"] = "month"
    chart["query"]["dimension"] = "status"  # text, not a date
    with pytest.raises(tk.ValidationError) as e:
        call("sse_dashboard_create", user, title="Not a date", config=config)
    assert "needs a date or timestamp dimension" in str(e.value)


def test_range_filter_is_checked(user, resource_id):
    config = config_for(resource_id)
    config["filters"].append({
        "id": "size", "label": "Size", "type": "range", "default_option": "all",
        "options": [
            {"id": "all", "label": "All", "all": True},
            {"id": "small", "label": "Under 1", "max": 1},
            {"id": "big", "label": "1 and over", "min": 1},
        ],
    })
    config["rows"][1]["cells"][0]["filter_bindings"] = {"size": "mw"}
    created = call("sse_dashboard_create", user, title="Ranges", config=config)
    assert created["config"]["filters"][-1]["type"] == "range"

    config["filters"][-1]["options"].append({"id": "bad", "label": "Bad", "min": 5, "max": 2})
    with pytest.raises(tk.ValidationError) as e:
        call("sse_dashboard_create", user, title="Bad range", config=config)
    assert "minimum must be lower than maximum" in str(e.value)

    config["filters"][-1]["options"].pop()
    config["rows"][1]["cells"][0]["filter_bindings"] = {"size": "status"}
    with pytest.raises(tk.ValidationError) as e:
        call("sse_dashboard_create", user, title="Range on text", config=config)
    assert "range filters need a number column" in str(e.value)
