"""my_access_requests: a requester reads their own decisions, and only theirs."""

import pytest
from flask_login import login_user

import ckan.model as model
import ckan.plugins.toolkit as tk
from ckan.tests import factories

from ckanext.sse.model import PackageAccessRequest

pytestmark = [
    pytest.mark.ckan_config("ckan.plugins", "datastore sse"),
    pytest.mark.usefixtures("sse_tables", "clean_index", "with_plugins"),
]


def signed_in(app, user_name):
    ctx = app.flask_app.test_request_context(
        "/", environ_overrides={"beaker.session": {}})
    ctx.push()
    login_user(model.User.get(user_name))
    return ctx


def make_request(user, org, dataset, message, status="pending", reason=None):
    req = PackageAccessRequest.create(
        package_id=dataset["id"], user_id=user["id"], org_id=org["id"],
        message=message)
    if status != "pending":
        PackageAccessRequest.update_status(req.id, status, reason, user["id"])
    return req


@pytest.fixture
def scene():
    org = factories.Organization()
    dataset = factories.Dataset(owner_org=org["id"])
    return {
        "org": org,
        "dataset": dataset,
        "jane": factories.User(name="jane"),
        "other": factories.User(name="other"),
    }


class TestMyAccessRequests:
    def test_returns_status_and_reason_for_the_caller(self, app, scene):
        make_request(scene["jane"], scene["org"], scene["dataset"], "please",
                     status="rejected", reason="Not for commercial use")
        ctx = signed_in(app, "jane")
        try:
            result = tk.get_action("my_access_requests")({}, {})
        finally:
            ctx.pop()
        assert len(result) == 1
        assert result[0]["status"] == "rejected"
        assert result[0]["rejection_message"] == "Not for commercial use"
        assert result[0]["package_name"] == scene["dataset"]["name"]

    def test_never_returns_another_users_requests(self, app, scene):
        make_request(scene["other"], scene["org"], scene["dataset"], "mine",
                     status="rejected", reason="private reason")
        ctx = signed_in(app, "jane")
        try:
            result = tk.get_action("my_access_requests")({}, {})
        finally:
            ctx.pop()
        assert result == []

    def test_no_reason_while_pending(self, app, scene):
        make_request(scene["jane"], scene["org"], scene["dataset"], "please")
        ctx = signed_in(app, "jane")
        try:
            result = tk.get_action("my_access_requests")({}, {})
        finally:
            ctx.pop()
        assert result[0]["status"] == "pending"
        assert result[0]["rejection_message"] is None

    def test_anonymous_is_refused(self, app):
        ctx = app.flask_app.test_request_context("/")
        ctx.push()
        try:
            with pytest.raises(tk.NotAuthorized):
                tk.get_action("my_access_requests")({"user": ""}, {})
        finally:
            ctx.pop()
