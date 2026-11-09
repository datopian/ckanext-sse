"""Access request history: every step kept with its time, actor and reason."""

from datetime import date, datetime, timedelta
from urllib.parse import urlsplit

import pytest

from ckan import model
from ckan.tests import factories

from ckanext.sse import action as sse_action
from ckanext.sse.blueprints import request_access_dashboard as dashboard
from ckanext.sse.model import PackageAccessRequest, PackageAccessRequestEvent

PASSWORD = "Tr0mb0ne-Yak!79"

pytestmark = [
    pytest.mark.ckan_config("ckan.plugins", "datastore sse"),
    pytest.mark.ckan_config("ckan.datastore.sqlsearch.enabled", "true"),
    pytest.mark.ckan_config("ckan.auth.allow_dataset_collaborators", "true"),
    pytest.mark.usefixtures(
        "sse_tables", "clean_index", "with_plugins", "no_schema", "no_mail"
    ),
]


@pytest.fixture
def no_schema(monkeypatch):
    """The SSE package_search/show hooks read the scheming schema, not loaded here."""
    monkeypatch.setattr(sse_action, "_get_dataset_schema_frequency_options", lambda: [])


@pytest.fixture
def no_mail(monkeypatch):
    monkeypatch.setattr(sse_action, "send_request_mail_to_org_admins", lambda d: True)
    monkeypatch.setattr(dashboard, "mail_rejected_user", lambda *a, **k: None)
    monkeypatch.setattr(sse_action, "mail_allowed_user", lambda *a, **k: None)
    monkeypatch.setattr(sse_action, "mail_rejected_user", lambda *a, **k: None)


def token_for(user):
    return factories.APIToken(user=user["name"])["token"]


@pytest.fixture
def scene():
    org_admin = factories.User(password=PASSWORD, email="admin@example.org")
    org = factories.Organization(
        users=[{"name": org_admin["name"], "capacity": "admin"}]
    )
    dataset = factories.Dataset(owner_org=org["id"])
    requester = factories.User(password=PASSWORD, email="r@example.org")
    return org_admin, org, dataset, requester


def request_access(app, dataset, requester, message="please"):
    resp = app.post(
        "/api/3/action/request_access_to_dataset",
        json={"package_id": dataset["id"], "message": message},
        headers={"Authorization": token_for(requester)},
    )
    assert resp.json.get("result", {}).get("success") is True, resp.json
    return PackageAccessRequest.get_by_package_user_and_status(
        dataset["id"], requester["id"], "pending"
    )[0].id


def decide(app, admin, request_id, action, reason=None):
    data = {"request_id": request_id, "action": action}
    if reason:
        data["rejection_message"] = reason
    return app.post(
        "/access_requests/update_status",
        data=data,
        headers={"Authorization": token_for(admin)},
        follow_redirects=False,
    )


def history(request_id):
    model.Session.expire_all()
    return [
        (e.action, e.actor.name if e.actor else None, e.reason)
        for e in PackageAccessRequest.get(request_id).events
    ]


def test_every_step_is_kept_in_order(app, scene):
    admin, _, dataset, requester = scene
    request_id = request_access(app, dataset, requester, "for a study")
    decide(app, admin, request_id, "approve")
    decide(app, admin, request_id, "revoke", "study finished")

    assert history(request_id) == [
        ("created", requester["name"], "for a study"),
        ("approved", admin["name"], None),
        ("revoked", admin["name"], "study finished"),
    ]
    events = PackageAccessRequest.get(request_id).events
    assert all(e.created_at for e in events)
    assert events[0].created_at <= events[1].created_at <= events[2].created_at
    assert not any(e.backfilled for e in events)
    assert PackageAccessRequest.get(request_id).status == "revoked"


def test_rejection_keeps_the_reason(app, scene):
    admin, _, dataset, requester = scene
    request_id = request_access(app, dataset, requester)
    decide(app, admin, request_id, "reject", "not eligible")
    assert history(request_id)[-1] == ("rejected", admin["name"], "not eligible")


def test_a_new_request_after_revocation_has_its_own_history(app, scene):
    admin, _, dataset, requester = scene
    first = request_access(app, dataset, requester)
    decide(app, admin, first, "approve")
    decide(app, admin, first, "revoke")
    second = request_access(app, dataset, requester)
    assert second != first
    assert history(second) == [("created", requester["name"], "please")]
    assert len(history(first)) == 3


def test_refused_decision_changes_nothing(app, scene):
    _, _, dataset, requester = scene
    request_id = request_access(app, dataset, requester)
    outsider = factories.User(password=PASSWORD)
    factories.Organization(users=[{"name": outsider["name"], "capacity": "admin"}])
    decide(app, outsider, request_id, "approve")
    assert history(request_id) == [("created", requester["name"], "please")]
    assert PackageAccessRequest.get(request_id).status == "pending"


def test_backfill_seeds_requests_made_before_history(scene):
    admin, org, dataset, requester = scene
    pending = PackageAccessRequest(
        package_id=dataset["id"], user_id=requester["id"], org_id=org["id"],
        message="old pending", status="pending",
    )
    rejected = PackageAccessRequest(
        package_id=dataset["id"], user_id=requester["id"], org_id=org["id"],
        message="old rejected", status="rejected",
        rejection_message="no", approved_or_rejected_by_user_id=admin["id"],
    )
    model.Session.add_all([pending, rejected])
    model.Session.commit()

    assert PackageAccessRequestEvent.backfill() == 2
    assert history(pending.id) == [("created", requester["name"], "old pending")]
    assert history(rejected.id) == [
        ("created", requester["name"], "old rejected"),
        ("rejected", admin["name"], "no"),
    ]
    decision = PackageAccessRequest.get(rejected.id).events[-1]
    assert decision.backfilled and decision.created_at is None

    assert PackageAccessRequestEvent.backfill() == 0
    assert len(history(rejected.id)) == 2


@pytest.fixture
def no_nav(app, monkeypatch):
    from ckan.lib import helpers

    # The SSE header links to plugins not loaded here (user groups, showcases).
    # Patched after the app is built, which reloads the helpers.
    monkeypatch.setitem(
        helpers.helper_functions, "build_nav_main", lambda *a, **k: ""
    )


def dashboard_page(app, user, query=""):
    return app.get(
        "/access_requests" + query, headers={"Authorization": token_for(user)}
    ).body


@pytest.mark.usefixtures("no_nav")
def test_dashboard_lists_by_status_with_the_last_decision(app, scene):
    admin, _, dataset, requester = scene
    request_id = request_access(app, dataset, requester)
    decide(app, admin, request_id, "approve")
    decide(app, admin, request_id, "revoke", "study finished")

    pending = dashboard_page(app, admin)
    assert request_id not in pending
    revoked = dashboard_page(app, admin, "?status=revoked")
    assert "/access_requests/{}/history".format(request_id) in revoked
    assert "Revoked by" in revoked and ">{}</a>".format(admin["name"]) in revoked
    assert "UTC UTC" not in revoked


@pytest.mark.usefixtures("no_nav")
def test_history_endpoint_shows_every_step(app, scene):
    admin, _, dataset, requester = scene
    request_id = request_access(app, dataset, requester, "for a study")
    decide(app, admin, request_id, "approve")
    decide(app, admin, request_id, "revoke", "study finished")

    body = app.get(
        "/access_requests/{}/history".format(request_id),
        headers={"Authorization": token_for(admin)},
    ).body
    assert [label in body for label in ("Requested", "Approved", "Revoked")] == [True] * 3
    assert "for a study" in body and "study finished" in body
    assert body.count(">{}</a>".format(admin["name"])) == 2


@pytest.mark.usefixtures("no_nav")
def test_history_endpoint_is_for_admins_of_the_requests_organisation(app, scene):
    _, _, dataset, requester = scene
    request_id = request_access(app, dataset, requester)
    outsider = factories.User(password=PASSWORD)
    factories.Organization(users=[{"name": outsider["name"], "capacity": "admin"}])
    url = "/access_requests/{}/history".format(request_id)

    assert app.get(url, headers={"Authorization": token_for(outsider)}).status_code == 403
    assert app.get(url, headers={"Authorization": token_for(requester)}).status_code == 403
    sysadmin = factories.Sysadmin(password=PASSWORD)
    assert app.get(url, headers={"Authorization": token_for(sysadmin)}).status_code == 200
    assert app.get(
        "/access_requests/missing/history",
        headers={"Authorization": token_for(sysadmin)},
    ).status_code == 404


def test_search_filters_sorts_and_pages(app, scene):
    admin, org, dataset, requester = scene
    other = factories.User(password=PASSWORD, fullname="Zed Quill", email="zq@example.org")
    second = factories.Dataset(owner_org=org["id"])
    first = request_access(app, dataset, requester)
    decide(app, admin, first, "reject", "no")
    by_other = request_access(app, second, other)
    newest = request_access(app, dataset, requester)
    ten_days_ago = datetime.utcnow() - timedelta(days=10)
    old = PackageAccessRequest.get(by_other)
    old.created_at = ten_days_ago
    for event in old.history_rows:
        event.created_at = ten_days_ago
    model.Session.commit()

    def ids(**kw):
        items, total, counts = PackageAccessRequest.search(org_ids=[org["id"]], **kw)
        return [r.id for r in items], total, counts

    found, total, counts = ids()
    assert total == 3 and counts == {
        "pending": 2, "approved": 0, "rejected": 1, "revoked": 0, "all": 3}
    # Latest activity first: the backdated request comes last.
    assert found[-1] == by_other
    assert ids(status="rejected")[0] == [first]
    assert ids(q="quill")[0] == [by_other]
    assert ids(q="ZQ@EXAMPLE")[0] == [by_other]
    assert ids(q="%")[0] == []
    assert sorted(ids(package_id=dataset["id"])[0]) == sorted([first, newest])
    today = date.today()
    assert by_other not in ids(requested_from=today)[0]
    assert ids(requested_to=today - timedelta(days=5))[0] == [by_other]
    assert ids(sort="requested")[0][0] == newest

    page_one, total, _ = ids(limit=2)
    page_two, _, _ = ids(limit=2, offset=2)
    assert total == 3 and len(page_one) == 2 and len(page_two) == 1
    assert not set(page_one) & set(page_two)

    outsider_org = factories.Organization()
    assert PackageAccessRequest.search(org_ids=[outsider_org["id"]])[1] == 0
    assert PackageAccessRequest.search(org_ids=None)[1] == 3


@pytest.mark.parametrize("target, expected", [
    ("/access_requests?status=all&page=2", "/access_requests?status=all&page=2"),
    ("https://evil.example/access_requests", "/access_requests"),
    ("//evil.example/access_requests", "/access_requests"),
    ("/access_requests/..//evil.example", "/access_requests"),
    ("", "/access_requests"),
])
def test_decisions_return_only_to_the_dashboard(app, scene, target, expected):
    admin, _, dataset, requester = scene
    request_id = request_access(app, dataset, requester)
    resp = app.post(
        "/access_requests/update_status",
        data={"request_id": request_id, "action": "approve", "return_to": target},
        headers={"Authorization": token_for(admin)},
        follow_redirects=False,
    )
    assert resp.status_code == 302
    location = urlsplit(resp.headers["Location"])
    assert location.path + ("?" + location.query if location.query else "") == expected
