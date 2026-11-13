"""Personal dashboards: access rules and config validation."""

import base64
import copy

import pytest

from ckan import logic, model
from ckan.tests import factories, helpers

from ckanext.sse import action as sse_action
from ckanext.sse.model import Dashboard, DashboardPreview

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


def datastore_resource(owner, private=False, restricted=False, geospatial=True):
    dataset = factories.Dataset(user=owner, private=private,
                                owner_org=factories.Organization(user=owner)["id"])
    if restricted:
        # Scheming keeps is_restricted as a package extra.
        helpers.call_action("package_patch", {"user": owner["name"]}, id=dataset["id"],
                            extras=[{"key": "is_restricted", "value": "true"}])
    resource = factories.Resource(package_id=dataset["id"], name="dispatch",
                                  url="http://example.com/dispatch.csv",
                                  is_geospatial=str(geospatial))
    result = helpers.call_action(
        "datastore_create",
        resource_id=resource["id"],
        fields=[
            {"id": "status", "type": "text"},
            {"id": "mw", "type": "numeric"},
            {"id": "dispatched_at", "type": "timestamp"},
            {"id": "lat", "type": "numeric"},
            {"id": "lon", "type": "numeric"},
            {"id": "geometry", "type": "text"},
        ],
        records=[{"status": "Active", "mw": 1.5, "dispatched_at": "2026-11-01",
                  "lat": 57.1, "lon": -2.1, "geometry": "POINT (-2.1 57.1)"}],
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
    assert listed[0]["layout"] == [["kpi", "text"], ["chart"], ["map", None]]
    assert listed[0]["resources"] == [resource_id]

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


def _map_config(resource_id, layer):
    config = config_for(resource_id)
    config["rows"][2]["cells"][0]["layers"] = [dict({"id": "l1", "resource_id": resource_id}, **layer)]
    return config


def test_shapes_layers_read_a_geometry_column(user, resource_id):
    layer = {"kind": "shapes", "geometry": "geometry", "tooltip": ["status"],
             "filters": [{"column": "mw", "operation": ">", "value": 1}],
             "filter_bindings": {"status": "status"}}
    call("sse_dashboard_create", user, title="Shapes", config=_map_config(resource_id, layer))

    assert _errors(user, _map_config(resource_id, dict(layer, geometry="shape"))) == (
        "rows[2].cells[0].layers[0].geometry: unknown column 'shape'")


def test_map_layer_conditions_are_checked(user, resource_id):
    layer = {"kind": "points", "lat": "lat", "lon": "lon",
             "filters": [{"column": "nope", "operation": "=", "value": "x"}]}
    assert _errors(user, _map_config(resource_id, layer)) == (
        "rows[2].cells[0].layers[0].filters[0].column: unknown column 'nope'")


def test_map_layers_need_geospatial_data(user):
    resource_id = datastore_resource(factories.Sysadmin(password=PASSWORD), geospatial=False)
    for layer in ({"kind": "points", "lat": "lat", "lon": "lon"},
                  {"kind": "shapes", "geometry": "geometry"}):
        assert "rows[2].cells[0].layers[0].resource_id: is not marked as geospatial data" in _errors(
            user, _map_config(resource_id, layer))


def test_chart_date_group_is_checked(user, resource_id):
    config = config_for(resource_id)
    chart = config["rows"][1]["cells"][0]
    chart["query"]["date_group"] = "fortnight"
    with pytest.raises(logic.ValidationError) as e:
        call("sse_dashboard_create", user, title="Bad period", config=config)
    assert "fortnight" not in str(e.value) and "date_group" in str(e.value)

    chart["query"]["date_group"] = "month"
    chart["query"]["dimension"] = "status"  # text, not a date
    with pytest.raises(logic.ValidationError) as e:
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
    with pytest.raises(logic.ValidationError) as e:
        call("sse_dashboard_create", user, title="Bad range", config=config)
    assert "minimum must be lower than maximum" in str(e.value)

    config["filters"][-1]["options"].pop()
    config["rows"][1]["cells"][0]["filter_bindings"] = {"size": "status"}
    with pytest.raises(logic.ValidationError) as e:
        call("sse_dashboard_create", user, title="Range on text", config=config)
    assert "range filters need a number column" in str(e.value)


# Showcasing in data assets

@pytest.fixture
def asset():
    """A public data asset with an editor and a plain member."""
    editor = factories.User(password=PASSWORD)
    member = factories.User(password=PASSWORD)
    org = factories.Organization(users=[
        {"name": editor["name"], "capacity": "editor"},
        {"name": member["name"], "capacity": "member"},
    ])
    dataset = factories.Dataset(owner_org=org["id"])
    return {"dataset": dataset, "editor": editor, "member": member}


def personal(owner, resource_id, title="Dispatch"):
    return call("sse_dashboard_create", owner, title=title, config=config_for(resource_id))


def test_showcase_moves_a_dashboard_into_the_data_asset(asset, resource_id):
    editor = asset["editor"]
    dashboard = personal(editor, resource_id)

    shown = call("sse_dashboard_showcase", editor, id=dashboard["id"], package_id=asset["dataset"]["name"])

    assert shown["package_id"] == asset["dataset"]["id"]
    assert shown["owner_user_id"] is None
    assert shown["visibility"] == "private"
    assert shown["slug"] == "dispatch"
    assert shown["package"]["name"] == asset["dataset"]["name"]
    # It leaves My dashboards and cannot be showcased again.
    assert call("sse_dashboard_list", editor) == []
    with pytest.raises(logic.ValidationError):
        call("sse_dashboard_showcase", editor, id=dashboard["id"], package_id=asset["dataset"]["id"])


def test_showcase_needs_edit_rights_on_the_data_asset(asset, resource_id):
    member = asset["member"]
    dashboard = personal(member, resource_id)
    with pytest.raises(logic.NotAuthorized):
        call("sse_dashboard_showcase", member, id=dashboard["id"], package_id=asset["dataset"]["id"])


def test_showcase_names_widgets_whose_data_is_not_open(asset, resource_id):
    editor = asset["editor"]
    dashboard = personal(editor, resource_id)
    # The data becomes restricted after the dashboard was saved.
    package_id = model.Resource.get(resource_id).package_id
    helpers.call_action("package_patch", id=package_id, extras=[{"key": "is_restricted", "value": "true"}])
    with pytest.raises(logic.ValidationError) as e:
        call("sse_dashboard_showcase", editor, id=dashboard["id"], package_id=asset["dataset"]["id"])
    message = str(e.value)
    assert "Total MW" in message and "Untitled chart" in message and "Map layer 1" in message


def test_editors_manage_and_viewers_see_public_ones(asset, resource_id):
    editor, member = asset["editor"], asset["member"]
    other = factories.User(password=PASSWORD)
    shown = call("sse_dashboard_showcase", editor, id=personal(editor, resource_id)["id"],
                 package_id=asset["dataset"]["id"])

    # Private: editors only.
    assert [d["id"] for d in call("sse_dashboard_list", member, package_id=asset["dataset"]["id"])] == []
    with pytest.raises(logic.NotAuthorized):
        call("sse_dashboard_show", other, id=shown["id"])

    call("sse_dashboard_update", editor, id=shown["id"], visibility="public")

    listed = call("sse_dashboard_list", other, package_id=asset["dataset"]["name"])
    assert [d["id"] for d in listed] == [shown["id"]] and listed[0]["can_edit"] is False
    by_slug = call("sse_dashboard_show", other, package_id=asset["dataset"]["name"], slug="dispatch")
    assert by_slug["id"] == shown["id"] and by_slug["can_edit"] is False
    with pytest.raises(logic.NotAuthorized):
        call("sse_dashboard_update", other, id=shown["id"], title="Mine now")

    # Another editor of the data asset can manage it, not only whoever showcased it.
    second = factories.User(password=PASSWORD)
    helpers.call_action("organization_member_create", id=asset["dataset"]["owner_org"],
                        username=second["name"], role="editor")
    assert call("sse_dashboard_update", second, id=shown["id"], title="Renamed")["title"] == "Renamed"
    assert [d["id"] for d in call("sse_dashboard_list", second, showcased=True)] == [shown["id"]]


def test_visibility_only_for_showcased(user, resource_id):
    dashboard = personal(user, resource_id)
    with pytest.raises(logic.ValidationError):
        call("sse_dashboard_update", user, id=dashboard["id"], visibility="public")


def test_reorder_and_unique_slugs(asset, resource_id):
    editor = asset["editor"]
    package_id = asset["dataset"]["id"]
    a = call("sse_dashboard_showcase", editor, id=personal(editor, resource_id)["id"], package_id=package_id)
    b = call("sse_dashboard_showcase", editor, id=personal(editor, resource_id)["id"], package_id=package_id)
    assert (a["slug"], b["slug"]) == ("dispatch", "dispatch-2")
    assert (a["position"], b["position"]) == (0, 1)

    assert call("sse_dashboard_reorder", editor, package_id=package_id, order=[b["id"], a["id"]]) == [b["id"], a["id"]]
    with pytest.raises(logic.ValidationError):
        call("sse_dashboard_reorder", editor, package_id=package_id, order=[a["id"]])
    with pytest.raises(logic.NotAuthorized):
        call("sse_dashboard_reorder", asset["member"], package_id=package_id, order=[a["id"], b["id"]])


def test_deleted_data_asset_hides_its_dashboards(asset, resource_id):
    editor = asset["editor"]
    shown = call("sse_dashboard_showcase", editor, id=personal(editor, resource_id)["id"],
                 package_id=asset["dataset"]["id"])
    helpers.call_action("package_delete", id=asset["dataset"]["id"])
    with pytest.raises((logic.NotFound, logic.NotAuthorized)):
        call("sse_dashboard_show", editor, id=shown["id"])
    # Purging the data asset removes them.
    helpers.call_action("dataset_purge", id=asset["dataset"]["id"])
    assert Dashboard.get(shown["id"]) is None


def test_showcase_targets_are_editable_data_assets(asset):
    targets = call("sse_dashboard_showcase_targets", asset["editor"])
    assert asset["dataset"]["id"] in [t["id"] for t in targets]
    assert call("sse_dashboard_showcase_targets", asset["member"]) == []


# Card previews

WEBP = base64.b64encode(b"RIFF\x1a\x00\x00\x00WEBPVP8 " + b"\x00" * 14).decode()


def test_preview_is_stored_and_listed(user, resource_id):
    dashboard = personal(user, resource_id)
    assert call("sse_dashboard_list", user)[0]["preview_at"] is None
    with pytest.raises(logic.NotFound):
        call("sse_dashboard_preview_show", user, id=dashboard["id"])

    saved = call("sse_dashboard_preview_update", user, id=dashboard["id"], image=WEBP)

    assert call("sse_dashboard_list", user)[0]["preview_at"] == saved["preview_at"]
    assert call("sse_dashboard_show", user, id=dashboard["id"])["preview_at"] == saved["preview_at"]
    shown = call("sse_dashboard_preview_show", user, id=dashboard["id"])
    assert shown["mimetype"] == "image/webp" and shown["image"] == WEBP


@pytest.mark.parametrize("image", [
    "not base64!",
    base64.b64encode(b"<svg onload=alert(1)>").decode(),
    base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"\x00" * (512 * 1024)).decode(),
])
def test_preview_must_be_a_small_raster_image(user, resource_id, image):
    dashboard = personal(user, resource_id)
    with pytest.raises(logic.ValidationError):
        call("sse_dashboard_preview_update", user, id=dashboard["id"], image=image)


def test_preview_follows_the_dashboard_access_rules(asset, resource_id):
    editor, member = asset["editor"], asset["member"]
    dashboard = personal(editor, resource_id)
    call("sse_dashboard_preview_update", editor, id=dashboard["id"], image=WEBP)
    # Personal: its owner only.
    with pytest.raises(logic.NotAuthorized):
        call("sse_dashboard_preview_update", member, id=dashboard["id"], image=WEBP)
    with pytest.raises(logic.NotAuthorized):
        call("sse_dashboard_preview_show", member, id=dashboard["id"])

    call("sse_dashboard_showcase", editor, id=dashboard["id"], package_id=asset["dataset"]["id"])
    outsider = factories.User(password=PASSWORD)
    with pytest.raises(logic.NotAuthorized):
        call("sse_dashboard_preview_show", outsider, id=dashboard["id"])
    call("sse_dashboard_update", editor, id=dashboard["id"], visibility="public")
    # Public showcased cards are listed to whoever sees the data asset.
    assert call("sse_dashboard_preview_show", outsider, id=dashboard["id"])["image"] == WEBP
    assert call("sse_dashboard_list", outsider, package_id=asset["dataset"]["id"])[0]["preview_at"]


def test_preview_goes_with_its_dashboard(user, resource_id):
    dashboard = personal(user, resource_id)
    call("sse_dashboard_preview_update", user, id=dashboard["id"], image=WEBP)
    call("sse_dashboard_delete", user, id=dashboard["id"])
    model.Session.expire_all()
    assert DashboardPreview.get(dashboard["id"]) is None


# Moving between data assets

def _second_asset(editor):
    org = factories.Organization(users=[{"name": editor["name"], "capacity": "editor"}])
    return factories.Dataset(owner_org=org["id"])


def test_move_to_another_data_asset_keeps_the_old_address(asset, resource_id):
    editor = asset["editor"]
    target = _second_asset(editor)
    shown = call("sse_dashboard_showcase", editor, id=personal(editor, resource_id)["id"],
                 package_id=asset["dataset"]["id"])
    call("sse_dashboard_update", editor, id=shown["id"], visibility="public")

    moved = call("sse_dashboard_move", editor, id=shown["id"], package_id=target["name"])

    assert moved["package_id"] == target["id"] and moved["visibility"] == "private"
    assert call("sse_dashboard_list", editor, package_id=asset["dataset"]["id"]) == []
    assert [d["id"] for d in call("sse_dashboard_list", editor, package_id=target["id"])] == [shown["id"]]
    old = call("sse_dashboard_show", editor, package_id=asset["dataset"]["name"], slug="dispatch")
    assert old["id"] == shown["id"] and old["package"]["name"] == target["name"]
    # A new insight may take the old slug; it then wins over the redirect.
    again = call("sse_dashboard_showcase", editor, id=personal(editor, resource_id)["id"],
                 package_id=asset["dataset"]["id"])
    assert again["slug"] == "dispatch"
    assert call("sse_dashboard_show", editor, package_id=asset["dataset"]["id"], slug="dispatch")["id"] == again["id"]


def test_move_needs_edit_rights_on_both_data_assets(asset, resource_id):
    editor = asset["editor"]
    shown = call("sse_dashboard_showcase", editor, id=personal(editor, resource_id)["id"],
                 package_id=asset["dataset"]["id"])
    elsewhere = factories.Dataset(owner_org=factories.Organization()["id"])
    with pytest.raises(logic.NotAuthorized):
        call("sse_dashboard_move", editor, id=shown["id"], package_id=elsewhere["id"])
    # An editor of the target only, not of where it is now.
    outsider = factories.User(password=PASSWORD)
    with pytest.raises(logic.NotAuthorized):
        call("sse_dashboard_move", outsider, id=shown["id"], package_id=_second_asset(outsider)["id"])


def test_move_is_for_showcased_dashboards_only(asset, resource_id):
    editor = asset["editor"]
    dashboard = personal(editor, resource_id)
    with pytest.raises(logic.ValidationError):
        call("sse_dashboard_move", editor, id=dashboard["id"], package_id=asset["dataset"]["id"])
    call("sse_dashboard_showcase", editor, id=dashboard["id"], package_id=asset["dataset"]["id"])
    with pytest.raises(logic.ValidationError):
        call("sse_dashboard_move", editor, id=dashboard["id"], package_id=asset["dataset"]["name"])
