"""Tests for ckanext.sse.token_scope (#325, #331).

These mint real CKAN API tokens, so the ini used to run them must configure the
API-token JWT secret (``api_token.jwt.encode.secret`` /
``api_token.jwt.decode.secret``); the Docker development ini already does.
"""

import pytest

import ckan.lib.api_token as api_token
import ckan.model as model
import ckan.plugins.toolkit as toolkit
from ckan.tests import factories

from ckanext.sse import token_scope as ts


def make_token(user_name, name):
    """A raw API token string for ``user_name`` with the given ``name``."""
    result = toolkit.get_action("api_token_create")(
        {"ignore_auth": True, "model": model, "user": user_name},
        {"user": user_name, "name": name},
    )
    return result["token"]


def action_context(app, raw_token, action):
    """A request context that looks like an action-API call with a token."""
    return app.flask_app.test_request_context(
        "/api/3/action/{}".format(action),
        method="POST",
        headers={"Authorization": raw_token},
        environ_overrides={"beaker.session": {}},
    )


@pytest.mark.usefixtures("with_plugins", "sse_tables")
class TestAllowlists:
    def test_frontend_allows_the_audited_actions(self):
        for action in ("package_show", "package_list", "package_search",
                       "resource_show", "user_extras", "user_show",
                       # the reads that carry the token in the data explorer,
                       # map and viz builders -- omitting these 403s those pages
                       "datastore_search_sql", "datastore_search",
                       "datastore_info",
                       "group_show", "organization_show", "license_list",
                       "data_reuse_create", "request_access_to_dataset",
                       "follow_dataset",
                       # the frontend triggers Smart Meter token regeneration
                       "smart_meter_token_create"):
            assert action in ts.FRONTEND_TOKEN_ACTIONS

    def test_frontend_blocks_every_write_and_admin_action(self):
        """The point of scoping: a leaked frontend token cannot do these."""
        for action in ("package_create", "package_update", "package_patch",
                       "package_delete", "resource_create", "resource_delete",
                       "datastore_create", "datastore_upsert",
                       "datastore_delete", "user_create", "user_update",
                       "user_patch", "organization_create",
                       "package_collaborator_create",
                       # must never be able to mint another token
                       "api_token_create", "api_token_revoke",
                       "api_token_list"):
            assert action not in ts.FRONTEND_TOKEN_ACTIONS

    def test_smart_meter_is_user_extras_only(self):
        assert ts.SMART_METER_TOKEN_ACTIONS == frozenset({"user_extras"})


@pytest.mark.usefixtures("with_plugins", "sse_tables")
class TestEnforcement:
    def test_a_request_with_no_token_is_untouched(self, app):
        with app.flask_app.test_request_context(
                "/api/3/action/package_create",
                environ_overrides={"beaker.session": {}}):
            assert ts.enforce_token_scope() is None

    def test_an_ordinary_named_token_keeps_full_rights(self, app):
        """A personal token is not one of ours, so it is left alone."""
        user = factories.User()
        raw = make_token(user["name"], "my personal token")
        with action_context(app, raw, "package_create"):
            assert ts.enforce_token_scope() is None

    def test_frontend_token_passes_an_allowlisted_action(self, app):
        user = factories.User()
        raw = make_token(user["name"], "frontend_token")
        with action_context(app, raw, "package_show"):
            assert ts.enforce_token_scope() is None

    def test_frontend_token_is_blocked_from_a_write(self, app):
        user = factories.User()
        raw = make_token(user["name"], "frontend_token")
        with action_context(app, raw, "package_create"):
            response = ts.enforce_token_scope()
        assert response is not None
        assert response.status_code == 403

    def test_smart_meter_token_allows_only_user_extras(self, app):
        user = factories.User()
        raw = make_token(user["name"], "smart_meter_token")
        with action_context(app, raw, "user_extras"):
            assert ts.enforce_token_scope() is None
        with action_context(app, raw, "package_show"):
            response = ts.enforce_token_scope()
        assert response is not None
        assert response.status_code == 403

    def test_a_scoped_token_is_denied_off_the_action_api(self, app):
        """These tokens have no business on any endpoint but their actions."""
        user = factories.User()
        raw = make_token(user["name"], "frontend_token")
        with app.flask_app.test_request_context(
                "/dataset", headers={"Authorization": raw},
                environ_overrides={"beaker.session": {}}):
            response = ts.enforce_token_scope()
        assert response is not None
        assert response.status_code == 403


@pytest.mark.usefixtures("with_plugins", "sse_tables")
class TestExpiry:
    """Only the frontend token is given a hard ``exp``; others never expire."""

    def test_frontend_token_carries_an_expiry(self):
        user = factories.User()
        raw = make_token(user["name"], "frontend_token")
        claims = api_token.decode(raw)
        assert claims is not None and "exp" in claims
        # exp is iat + the configured TTL (default 35 minutes). iat and exp are
        # stamped microseconds apart and each truncated to a whole second, so
        # allow a 1s slack rather than demanding exact equality.
        ttl = ts._frontend_token_ttl_seconds()
        assert ttl <= claims["exp"] - claims["iat"] <= ttl + 1

    def test_smart_meter_token_never_expires(self):
        user = factories.User()
        raw = make_token(user["name"], "smart_meter_token")
        claims = api_token.decode(raw)
        assert claims is not None and "exp" not in claims

    def test_a_personal_token_never_expires(self):
        user = factories.User()
        raw = make_token(user["name"], "my personal token")
        claims = api_token.decode(raw)
        assert claims is not None and "exp" not in claims

    def test_the_ttl_is_configurable(self, monkeypatch):
        monkeypatch.setenv("CKANEXT__SSE__FRONTEND_TOKEN_TTL_MINUTES", "10")
        user = factories.User()
        raw = make_token(user["name"], "frontend_token")
        claims = api_token.decode(raw)
        assert 10 * 60 <= claims["exp"] - claims["iat"] <= 10 * 60 + 1

    def test_a_zero_ttl_disables_the_expiry(self, monkeypatch):
        monkeypatch.setenv("CKANEXT__SSE__FRONTEND_TOKEN_TTL_MINUTES", "0")
        user = factories.User()
        raw = make_token(user["name"], "frontend_token")
        claims = api_token.decode(raw)
        assert "exp" not in claims
