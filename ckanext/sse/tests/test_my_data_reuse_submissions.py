"""Reuse feedback is stored on rejection and readable only by its submitter."""

import pytest
from flask_login import login_user

import ckan.model as model
import ckan.plugins.toolkit as tk
from ckan.tests import factories

import ckanext.sse.action as sse_action
from ckanext.sse.model import FormResponse

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


@pytest.fixture(autouse=True)
def no_mail(monkeypatch):
    monkeypatch.setattr(sse_action, "reuse_email_notification", lambda *a, **k: True)


@pytest.fixture
def scene():
    org = factories.Organization()
    dataset = factories.Dataset(owner_org=org["id"])
    return {
        "dataset": dataset,
        "jane": factories.User(name="jane"),
        "other": factories.User(name="other"),
        "mod": factories.Sysadmin(name="moderator"),
    }


def submit(user, dataset, title="EV heatmap"):
    return FormResponse.create(
        type="example", data={"title": title}, user_id=user["id"],
        package_id=dataset["id"], state="pending")


class TestMyDataReuseSubmissions:
    def test_rejection_feedback_is_stored_and_returned_to_submitter(self, app, scene):
        sub = submit(scene["jane"], scene["dataset"])
        ctx = signed_in(app, "moderator")
        try:
            tk.get_action("data_reuse_patch")(
                {"user": "moderator"},
                {"id": sub.id, "state": "rejected", "feedback": "Add the data source"})
        finally:
            ctx.pop()

        ctx = signed_in(app, "jane")
        try:
            result = tk.get_action("my_data_reuse_submissions")({}, {})
        finally:
            ctx.pop()
        assert result[0]["state"] == "rejected"
        assert result[0]["feedback"] == "Add the data source"
        assert result[0]["decided_at"]

    def test_feedback_stays_out_of_the_public_view(self, app, scene):
        sub = submit(scene["jane"], scene["dataset"])
        ctx = signed_in(app, "moderator")
        try:
            tk.get_action("data_reuse_patch")(
                {"user": "moderator"},
                {"id": sub.id, "state": "approved", "feedback": "internal note"})
            public = tk.get_action("data_reuse_show")({"user": ""}, {"id": sub.id})
        finally:
            ctx.pop()
        assert "feedback" not in public["data"]

    def test_never_returns_another_users_submissions(self, app, scene):
        submit(scene["other"], scene["dataset"])
        ctx = signed_in(app, "jane")
        try:
            result = tk.get_action("my_data_reuse_submissions")({}, {})
        finally:
            ctx.pop()
        assert result == []

    def test_anonymous_is_refused(self, app):
        ctx = app.flask_app.test_request_context("/")
        ctx.push()
        try:
            with pytest.raises(tk.NotAuthorized):
                tk.get_action("my_data_reuse_submissions")({"user": ""}, {})
        finally:
            ctx.pop()
