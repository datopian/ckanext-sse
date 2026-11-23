"""Insights in collections: linking, featuring and the public collection list."""

import pytest

from ckan import logic, model
from ckan.tests import factories, helpers

from ckanext.sse.model import DashboardGroup
from ckanext.sse.tests.test_dashboards import (  # noqa: F401 (fixtures)
    PASSWORD,
    call,
    config_for,
    datastore_resource,
    no_schema,
    resource_id,
)

pytestmark = [
    pytest.mark.ckan_config("ckan.plugins", "activity datastore sse"),
    pytest.mark.usefixtures("sse_tables", "clean_index", "with_plugins", "no_schema"),
]


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
    return {"dataset": dataset, "org": org, "editor": editor, "member": member}


@pytest.fixture
def collections():
    # Collections are listed by title.
    return [factories.Group(name="connections", title="Connections"),
            factories.Group(name="flexibility", title="Flexibility")]


def insight(asset, resource_id, title="Dispatch", visibility="public"):
    """A dashboard showcased in the asset's data asset."""
    editor = asset["editor"]
    dashboard = call("sse_dashboard_create", editor, title=title, config=config_for(resource_id))
    call("sse_dashboard_showcase", editor, id=dashboard["id"], package_id=asset["dataset"]["id"])
    return call("sse_dashboard_update", editor, id=dashboard["id"], visibility=visibility)


def names(groups):
    return [(g["name"], g["featured"]) for g in groups]


def test_an_insight_can_be_in_several_collections(asset, resource_id, collections):
    editor = asset["editor"]
    shown = insight(asset, resource_id)

    updated = call("sse_dashboard_update", editor, id=shown["id"],
                   groups=["connections", {"name": "flexibility", "featured": True}])

    assert names(updated["groups"]) == [("connections", False), ("flexibility", True)]
    shown = call("sse_dashboard_show", editor, id=shown["id"])
    assert names(shown["groups"]) == [("connections", False), ("flexibility", True)]
    listed = call("sse_dashboard_list", editor, package_id=asset["dataset"]["id"])
    assert names(listed[0]["groups"]) == [("connections", False), ("flexibility", True)]
    for group in ("connections", "flexibility"):
        assert [d["id"] for d in call("sse_dashboard_group_list", group_id=group)] == [shown["id"]]


def test_groups_replace_the_previous_ones(asset, resource_id, collections):
    editor = asset["editor"]
    shown = insight(asset, resource_id)
    call("sse_dashboard_update", editor, id=shown["id"], groups=["connections", "flexibility"])

    updated = call("sse_dashboard_update", editor, id=shown["id"], groups=["flexibility"])
    assert names(updated["groups"]) == [("flexibility", False)]
    assert call("sse_dashboard_group_list", group_id="connections") == []

    updated = call("sse_dashboard_update", editor, id=shown["id"], groups=[])
    assert updated["groups"] == []
    # Leaving groups out leaves them as they are.
    call("sse_dashboard_update", editor, id=shown["id"], groups=["connections"])
    updated = call("sse_dashboard_update", editor, id=shown["id"], title="Renamed")
    assert names(updated["groups"]) == [("connections", False)]


def test_groups_can_be_sent_as_json(asset, resource_id, collections):
    shown = insight(asset, resource_id)
    updated = call("sse_dashboard_update", asset["editor"], id=shown["id"],
                   groups='[{"name": "connections", "featured": true}]')
    assert names(updated["groups"]) == [("connections", True)]


def test_only_showcased_dashboards_can_be_in_collections(asset, resource_id, collections):
    editor = asset["editor"]
    dashboard = call("sse_dashboard_create", editor, title="Mine", config=config_for(resource_id))
    with pytest.raises(logic.ValidationError) as e:
        call("sse_dashboard_update", editor, id=dashboard["id"], groups=["connections"])
    assert "groups" in e.value.error_dict


def test_unknown_collections_and_organizations_are_rejected(asset, resource_id, collections):
    editor = asset["editor"]
    shown = insight(asset, resource_id)
    for groups in (["nowhere"], [asset["org"]["name"]], "connections", [{"featured": True}]):
        with pytest.raises(logic.ValidationError) as e:
            call("sse_dashboard_update", editor, id=shown["id"], groups=groups)
        assert "groups" in e.value.error_dict
    # Nothing was changed by the refused calls.
    assert call("sse_dashboard_show", editor, id=shown["id"])["groups"] == []


def test_collections_are_capped(asset, resource_id):
    shown = insight(asset, resource_id)
    groups = [factories.Group()["name"] for _ in range(21)]
    with pytest.raises(logic.ValidationError):
        call("sse_dashboard_update", asset["editor"], id=shown["id"], groups=groups)


def test_only_the_insights_editors_set_its_collections(asset, resource_id, collections):
    shown = insight(asset, resource_id)
    for user in (asset["member"], factories.User(password=PASSWORD), None):
        with pytest.raises(logic.NotAuthorized):
            call("sse_dashboard_update", user, id=shown["id"], groups=["connections"])
    # Sysadmins can, as for every other insight change.
    updated = call("sse_dashboard_update", factories.Sysadmin(password=PASSWORD),
                   id=shown["id"], groups=["connections"])
    assert names(updated["groups"]) == [("connections", False)]


def test_featuring_takes_the_place_from_another_insight(asset, resource_id, collections):
    editor = asset["editor"]
    first = insight(asset, resource_id, title="First")
    second = insight(asset, resource_id, title="Second")
    call("sse_dashboard_update", editor, id=first["id"],
         groups=[{"name": "connections", "featured": True}, {"name": "flexibility", "featured": True}])

    call("sse_dashboard_update", editor, id=second["id"],
         groups=[{"name": "connections", "featured": True}])

    first_groups = call("sse_dashboard_show", editor, id=first["id"])["groups"]
    # It lost the feature where the second took it, and kept it elsewhere.
    assert names(first_groups) == [("connections", False), ("flexibility", True)]
    listed = call("sse_dashboard_group_list", group_id="connections")
    assert [(d["title"], d["featured"]) for d in listed] == [("Second", True), ("First", False)]


def test_collection_list_puts_the_featured_first_then_the_latest(asset, resource_id, collections):
    editor = asset["editor"]
    older = insight(asset, resource_id, title="Older")
    pinned = insight(asset, resource_id, title="Pinned")
    newer = insight(asset, resource_id, title="Newer")
    call("sse_dashboard_update", editor, id=pinned["id"], groups=[{"name": "connections", "featured": True}])
    call("sse_dashboard_update", editor, id=older["id"], groups=["connections"])
    call("sse_dashboard_update", editor, id=newer["id"], groups=["connections"])

    listed = call("sse_dashboard_group_list", group_id="connections")

    assert [d["title"] for d in listed] == ["Pinned", "Newer", "Older"]


def test_collection_list_is_public_and_shows_only_cards(asset, resource_id, collections):
    editor = asset["editor"]
    shown = insight(asset, resource_id)
    call("sse_dashboard_update", editor, id=shown["id"], groups=["connections"])

    # Signed out, as a collection page's server-side render is.
    listed = call("sse_dashboard_group_list", None, group_id="connections")

    assert len(listed) == 1
    card = listed[0]
    assert set(card) == {
        "id", "title", "slug", "description", "updated_at", "featured",
        "layout", "highlight_widget", "preview_at", "package",
    }
    assert card["package"]["name"] == asset["dataset"]["name"]
    assert card["package"]["organization"] == asset["org"]["name"]
    # config_for's first row is a key figure then a text widget.
    assert card["highlight_widget"] == {"id": "kpi", "type": "kpi"}
    assert card["layout"][0] == ["kpi", "text"]
    # Opening it, and its data, still needs signing in.
    with pytest.raises(logic.NotAuthorized):
        call("sse_dashboard_show", None, id=shown["id"])


def test_collection_list_leaves_out_insights_not_open_to_the_caller(asset, resource_id, collections):
    editor = asset["editor"]
    private_insight = insight(asset, resource_id, title="Draft", visibility="private")
    call("sse_dashboard_update", editor, id=private_insight["id"], groups=["connections"])
    hidden = factories.Dataset(owner_org=asset["org"]["id"], private=True)
    in_hidden = insight(asset, resource_id, title="Hidden asset")
    call("sse_dashboard_move", editor, id=in_hidden["id"], package_id=hidden["id"])
    call("sse_dashboard_update", editor, id=in_hidden["id"], visibility="public", groups=["connections"])

    # Private insights are left out even for editors: collection pages are public.
    assert [d["title"] for d in call("sse_dashboard_group_list", editor, group_id="connections")] == ["Hidden asset"]
    # A private data asset's insights are left out for those who cannot see it.
    assert call("sse_dashboard_group_list", None, group_id="connections") == []
    assert call("sse_dashboard_group_list", factories.User(password=PASSWORD), group_id="connections") == []


def test_text_only_insights_have_no_highlight_widget(asset, resource_id, collections):
    editor = asset["editor"]
    config = {"schema_version": 1, "filters": [], "rows": [
        {"id": "r1", "columns": 1, "cells": [{"id": "note", "type": "text", "markdown": "Hello"}]},
    ]}
    dashboard = call("sse_dashboard_create", editor, title="Notes", config=config)
    call("sse_dashboard_showcase", editor, id=dashboard["id"], package_id=asset["dataset"]["id"])
    call("sse_dashboard_update", editor, id=dashboard["id"], visibility="public", groups=["connections"])

    assert call("sse_dashboard_group_list", group_id="connections")[0]["highlight_widget"] is None


def test_unknown_or_deleted_collections_are_not_found(asset, resource_id, collections):
    editor = asset["editor"]
    shown = insight(asset, resource_id)
    call("sse_dashboard_update", editor, id=shown["id"], groups=["connections", "flexibility"])
    with pytest.raises(logic.ValidationError):
        call("sse_dashboard_group_list", group_id="")
    for group_id in ("nowhere", asset["org"]["name"]):
        with pytest.raises(logic.NotFound):
            call("sse_dashboard_group_list", group_id=group_id)

    # The activity plugin records who deleted it.
    sysadmin = factories.Sysadmin(password=PASSWORD)
    helpers.call_action("group_delete", {"user": sysadmin["name"]}, id="connections")

    with pytest.raises(logic.NotFound):
        call("sse_dashboard_group_list", group_id="connections")
    # A deleted collection drops out of the insight's collections.
    assert names(call("sse_dashboard_show", editor, id=shown["id"])["groups"]) == [("flexibility", False)]


def test_links_go_with_their_insight(asset, resource_id, collections):
    editor = asset["editor"]
    shown = insight(asset, resource_id)
    call("sse_dashboard_update", editor, id=shown["id"], groups=["connections"])

    call("sse_dashboard_delete", editor, id=shown["id"])

    assert model.Session.query(DashboardGroup).count() == 0
    assert call("sse_dashboard_group_list", group_id="connections") == []


def test_moving_an_insight_keeps_its_collections(asset, resource_id, collections):
    editor = asset["editor"]
    shown = insight(asset, resource_id)
    call("sse_dashboard_update", editor, id=shown["id"], groups=["connections"])
    other = factories.Dataset(owner_org=asset["org"]["id"])

    call("sse_dashboard_move", editor, id=shown["id"], package_id=other["id"])
    call("sse_dashboard_update", editor, id=shown["id"], visibility="public")

    listed = call("sse_dashboard_group_list", group_id="connections")
    assert [d["package"]["name"] for d in listed] == [other["name"]]
