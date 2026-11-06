"""Tests for the access request and admin action audit events (#363)."""

import json

import pytest

from ckan.tests import factories, helpers

from ckanext.sse import action as sse_action
from ckanext.sse.blueprints import request_access_dashboard as dashboard

PASSWORD = "Tr0mb0ne-Yak!79"

pytestmark = [
    pytest.mark.ckan_config("ckan.plugins", "datastore sse sse_audit"),
    pytest.mark.ckan_config("ckan.datastore.sqlsearch.enabled", "true"),
    pytest.mark.ckan_config("ckan.auth.allow_dataset_collaborators", "true"),
    pytest.mark.usefixtures("sse_tables", "clean_index", "with_plugins", "no_schema"),
]


@pytest.fixture
def no_schema(monkeypatch):
    """The SSE package_search/show hooks read the scheming schema, not loaded here."""
    monkeypatch.setattr(sse_action, "_get_dataset_schema_frequency_options", lambda: [])


@pytest.fixture
def events(capsys):
    def read(action):
        lines = capsys.readouterr().out.splitlines()
        parsed = [json.loads(l) for l in lines if l.startswith("{")]
        return [e for e in parsed if e.get("action") == action]

    return read


@pytest.fixture
def no_mail(monkeypatch):
    monkeypatch.setattr(sse_action, "send_request_mail_to_org_admins", lambda d: True)
    monkeypatch.setattr(dashboard, "mail_rejected_user", lambda *a, **k: None)
    monkeypatch.setattr(sse_action, "mail_allowed_user", lambda *a, **k: None)
    monkeypatch.setattr(sse_action, "mail_rejected_user", lambda *a, **k: None)


def token_for(user):
    return factories.APIToken(user=user["name"])["token"]


class TestAdminActions:
    def test_org_membership_change_is_recorded(self, events):
        admin = factories.Sysadmin(password=PASSWORD)
        member = factories.User(password=PASSWORD)
        org = factories.Organization()
        events("admin_action")
        helpers.call_action(
            "organization_member_create",
            {"user": admin["name"]},
            id=org["id"], username=member["name"], role="editor",
        )
        [event] = [
            e for e in events("admin_action")
            if e["admin_action"] == "organization_member_create"
        ]
        assert event["user_name"] == admin["name"]
        assert event["params"]["role"] == "editor"
        assert event["params"]["username"] == member["name"]

    def test_editing_your_own_profile_is_not_recorded(self, events):
        user = factories.User(password=PASSWORD)
        events("admin_action")
        helpers.call_action(
            "user_patch", {"user": user["name"]}, id=user["id"], about="hi"
        )
        assert not events("admin_action")

    def test_verified_user_toggle_is_recorded_without_profile_values(self, events):
        admin = factories.Sysadmin(password=PASSWORD)
        user = factories.User(password=PASSWORD)
        events("admin_action")
        helpers.call_action(
            "user_patch",
            {"user": admin["name"]},
            id=user["id"],
            email="new@example.com",
            plugin_extras={"ssen": {"is_verified_user": True}},
        )
        [event] = events("admin_action")
        assert event["admin_action"] == "user_update"
        assert event["target_user"] == user["name"]
        assert event["params"]["is_verified_user"] is True
        assert event["params"]["email"] == "<not logged>"
        assert "new@example.com" not in json.dumps(event)

    def test_passwords_are_never_logged(self, events):
        admin = factories.Sysadmin(password=PASSWORD)
        events("admin_action")
        helpers.call_action(
            "user_create", {"user": admin["name"]},
            name="made-by-admin", email="m@example.com", password=PASSWORD,
        )
        [event] = events("admin_action")
        assert event["params"]["password"] == "<not logged>"
        assert PASSWORD not in json.dumps(event)

    def test_self_registration_is_not_an_admin_action(self, events):
        events("admin_action")
        helpers.call_action(
            "user_create", {"user": ""},
            name="self-registered", email="s@example.com", password=PASSWORD,
        )
        assert not events("admin_action")

    def test_force_password_expiry_is_recorded(self, app, events):
        admin = factories.Sysadmin(password=PASSWORD)
        target = factories.User(password=PASSWORD)
        events("admin_action")
        app.post(
            "/ckan-admin/force-expire-password",
            data={"username": target["name"]},
            headers={"Authorization": token_for(admin)},
            follow_redirects=False,
        )
        [event] = [
            e for e in events("admin_action")
            if e["admin_action"] == "force_password_expiry"
        ]
        assert event["user_name"] == admin["name"]
        assert event["target_user"] == target["name"]


@pytest.mark.usefixtures("no_mail")
class TestAccessRequests:
    def setup_request(self, app):
        org_admin = factories.User(password=PASSWORD, email="admin@example.org")
        org = factories.Organization(
            users=[{"name": org_admin["name"], "capacity": "admin"}]
        )
        dataset = factories.Dataset(owner_org=org["id"])
        requester = factories.User(password=PASSWORD, email="r@example.org")
        resp = app.post(
            "/api/3/action/request_access_to_dataset",
            json={"package_id": dataset["id"], "message": "please"},
            headers={"Authorization": token_for(requester)},
        )
        assert resp.json.get("result", {}).get("success") is True, resp.json
        from ckanext.sse.model import PackageAccessRequest

        request_id = PackageAccessRequest.get_by_package_user_and_status(
            dataset["id"], requester["id"], "pending"
        )[0].id
        return org_admin, dataset, requester, request_id

    def decide(self, app, admin, request_id, action, reason=None):
        data = {"request_id": request_id, "action": action}
        if reason:
            data["rejection_message"] = reason
        return app.post(
            "/access_requests/update_status",
            data=data,
            headers={"Authorization": token_for(admin)},
            follow_redirects=False,
        )

    def test_request_is_recorded(self, app, events):
        _, dataset, requester, request_id = self.setup_request(app)
        [event] = events("access_request")
        assert event["request_action"] == "created"
        assert event["user_name"] == requester["name"]
        assert event["requester_name"] == requester["name"]
        assert event["request_id"] == request_id
        assert event["dataset_name"] == dataset["name"]

    def test_collaborator_added_on_approval_is_attributed_to_the_admin(self, app, events):
        admin, dataset, requester, request_id = self.setup_request(app)
        events("access_request")
        self.decide(app, admin, request_id, "approve")
        out = events("admin_action")
        approvals = [e for e in out if e.get("admin_action") == "package_collaborator_create"]
        assert approvals and approvals[0]["user_name"] == admin["name"]

    def test_approval_event(self, app, events):
        admin, dataset, requester, request_id = self.setup_request(app)
        events("access_request")
        self.decide(app, admin, request_id, "approve")
        [event] = events("access_request")
        assert event["request_action"] == "approved"
        assert event["status"] == "success"
        assert event["user_name"] == admin["name"]
        assert event["requester_name"] == requester["name"]

    def test_rejection_keeps_the_reason(self, app, events):
        admin, _, _, request_id = self.setup_request(app)
        events("access_request")
        self.decide(app, admin, request_id, "reject", "not eligible")
        [event] = events("access_request")
        assert event["request_action"] == "rejected"
        assert event["reason"] == "not eligible"

    def test_revocation_is_recorded(self, app, events):
        admin, _, _, request_id = self.setup_request(app)
        self.decide(app, admin, request_id, "approve")
        events("access_request")
        self.decide(app, admin, request_id, "revoke", "no longer needed")
        [event] = events("access_request")
        assert event["request_action"] == "revoked"
        assert event["user_name"] == admin["name"]

    def test_decision_by_a_non_admin_is_a_failure(self, app, events):
        _, _, _, request_id = self.setup_request(app)
        other_org_admin = factories.User(password=PASSWORD)
        factories.Organization(
            users=[{"name": other_org_admin["name"], "capacity": "admin"}]
        )
        events("access_request")
        self.decide(app, other_org_admin, request_id, "approve")
        [event] = events("access_request")
        assert event["status"] == "failure"
        assert event["user_name"] == other_org_admin["name"]
