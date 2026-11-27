"""The Daily Report admin page is for sysadmins only."""

import pytest

from ckan.tests import factories

PASSWORD = "quixotic wobble lantern"


@pytest.mark.usefixtures("with_plugins", "sse_tables")
class TestDailyReportPage:
    def test_sysadmin_can_open_it(self, app):
        admin = factories.Sysadmin(password=PASSWORD)
        response = app.get(
            "/ckan-admin/daily-report",
            headers={"Authorization": factories.APIToken(user=admin["name"])["token"]},
        )
        assert response.status_code == 200
        assert "Daily Report" in response.get_data(as_text=True)

    def test_normal_user_is_refused(self, app):
        user = factories.User(password=PASSWORD)
        response = app.get(
            "/ckan-admin/daily-report",
            headers={"Authorization": factories.APIToken(user=user["name"])["token"]},
        )
        assert response.status_code == 403

    def test_anonymous_is_refused(self, app):
        response = app.get("/ckan-admin/daily-report", follow_redirects=False)
        assert response.status_code in (302, 401, 403)
