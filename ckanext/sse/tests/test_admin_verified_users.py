"""Tests for the verified-user toggle in ckanext.sse.blueprints.admin."""

import pytest

import ckan.model as model
from ckan.tests import factories

PASSWORD = "quixotic wobble lantern"


@pytest.mark.usefixtures("with_plugins", "sse_tables")
class TestVerifiedUserToggle:
    def test_other_ssen_extras_are_kept(self, app):
        admin = factories.Sysadmin(password=PASSWORD)
        target = factories.User(password=PASSWORD)
        user_obj = model.User.get(target["id"])
        user_obj.plugin_extras = {"ssen": {
            "oid": "entra-oid", "current_session": "abc"}}
        model.Session.commit()

        response = app.post(
            "/ckan-admin/verified-users",
            data={"username": target["name"], "status": "true"},
            headers={"Authorization": factories.APIToken(
                user=admin["name"])["token"]},
            follow_redirects=False,
        )
        assert response.status_code == 302

        model.Session.expire_all()
        ssen = model.User.get(target["id"]).plugin_extras["ssen"]
        assert ssen["is_verified_user"] is True
        assert ssen["oid"] == "entra-oid"
        assert ssen["current_session"] == "abc"
