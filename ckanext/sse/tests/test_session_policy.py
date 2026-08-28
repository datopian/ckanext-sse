"""Tests for ckanext.sse.session_policy (AC-2.5, AC-11)."""

import time
from contextlib import contextmanager

import pytest
from flask_login import login_user

import ckan.model as model
from ckan.common import session
from ckan.tests import factories
from ckan.tests.helpers import changed_config

from ckanext.sse import session_policy as sp

PASSWORD = "quixotic wobble lantern"


@contextmanager
def request_for(app, url, user=None, last_seen=None):
    """A request context, optionally signed in and with an activity stamp.

    ``beaker.session`` is seeded because CKAN's session interface reads the
    session out of the WSGI environ, where the beaker middleware normally puts
    it; without it Flask hands back a ``NullSession`` that raises on write.
    """
    with app.flask_app.test_request_context(
            url, environ_overrides={"beaker.session": {}}):
        if user is not None:
            login_user(model.User.get(user["id"]))
        if last_seen is not None:
            session[sp.SESSION_KEY] = last_seen
        yield


@pytest.fixture
def user():
    return factories.User(password=PASSWORD,
                          email="session-test@example.com")


@pytest.mark.usefixtures("with_plugins", "sse_tables")
class TestIdleTimeout:
    def test_an_idle_session_is_ended(self, app, user):
        """AC-11 a: a lock after 15 minutes of inactivity."""
        stale = int(time.time()) - (sp.DEFAULT_IDLE_TIMEOUT_MINUTES * 60) - 1
        with request_for(app, "/dataset", user, last_seen=stale):
            response = sp.enforce_idle_timeout()
            assert response is not None
            assert response.status_code == 302
            assert "/user/login" in response.headers["Location"]

    def test_an_active_session_is_left_alone(self, app, user):
        recent = int(time.time()) - 60
        with request_for(app, "/dataset", user, last_seen=recent):
            assert sp.enforce_idle_timeout() is None

    def test_the_stamp_is_set_on_a_first_request(self, app, user):
        with request_for(app, "/dataset", user):
            assert sp.enforce_idle_timeout() is None
            assert session.get(sp.SESSION_KEY)

    def test_the_stamp_is_not_rewritten_on_every_request(self, app, user):
        """Beaker sends a Set-Cookie whenever the session changes."""
        recent = int(time.time()) - 5
        with request_for(app, "/dataset", user, last_seen=recent):
            sp.enforce_idle_timeout()
            assert session[sp.SESSION_KEY] == recent

    def test_the_stamp_is_refreshed_once_it_is_stale_enough(self, app, user):
        older = int(time.time()) - sp.STAMP_INTERVAL_SECONDS - 5
        with request_for(app, "/dataset", user, last_seen=older):
            sp.enforce_idle_timeout()
            assert session[sp.SESSION_KEY] > older

    def test_anonymous_requests_are_untouched(self, app):
        with request_for(app, "/dataset"):
            assert sp.enforce_idle_timeout() is None

    def test_the_api_is_exempt(self, app, user):
        """A client presenting a token is not idle at a screen."""
        stale = int(time.time()) - (sp.DEFAULT_IDLE_TIMEOUT_MINUTES * 60) - 1
        with request_for(app, "/api/3/action/status_show", user,
                         last_seen=stale):
            assert sp.enforce_idle_timeout() is None

    def test_the_timeout_can_be_switched_off(self, app, user):
        stale = int(time.time()) - 86400
        with changed_config("ckanext.sse.session.idle_timeout_minutes", "0"):
            with request_for(app, "/dataset", user, last_seen=stale):
                assert sp.enforce_idle_timeout() is None

    def test_the_timeout_is_configurable(self, app, user):
        stale = int(time.time()) - 120
        with changed_config("ckanext.sse.session.idle_timeout_minutes", "1"):
            with request_for(app, "/dataset", user, last_seen=stale):
                assert sp.enforce_idle_timeout() is not None

    def test_a_broken_setting_falls_back_to_the_default(self):
        with changed_config("ckanext.sse.session.idle_timeout_minutes",
                            "not a number"):
            assert sp.idle_timeout_seconds() == \
                sp.DEFAULT_IDLE_TIMEOUT_MINUTES * 60


@pytest.mark.usefixtures("with_plugins", "sse_tables")
class TestAbsoluteTimeout:
    def _cap(self):
        return sp.DEFAULT_MAX_SESSION_HOURS * 3600

    def test_a_session_past_the_cap_is_ended(self, app, user):
        """AC-12: terminate after a maximum of 8 hours."""
        old = int(time.time()) - self._cap() - 1
        with request_for(app, "/dataset", user):
            session[sp.SESSION_START_KEY] = old
            response = sp.enforce_absolute_timeout()
            assert response is not None
            assert response.status_code == 302
            assert "/user/login" in response.headers["Location"]

    def test_a_session_within_the_cap_is_left_alone(self, app, user):
        with request_for(app, "/dataset", user):
            session[sp.SESSION_START_KEY] = int(time.time()) - 60
            assert sp.enforce_absolute_timeout() is None

    def test_activity_does_not_extend_the_cap(self, app, user):
        """A refresh must not push the session past the absolute limit."""
        old = int(time.time()) - self._cap() - 1
        with request_for(app, "/dataset", user, last_seen=int(time.time())):
            session[sp.SESSION_START_KEY] = old
            assert sp.enforce_absolute_timeout() is not None

    def test_the_start_is_seeded_on_a_first_request(self, app, user):
        with request_for(app, "/dataset", user):
            assert sp.enforce_absolute_timeout() is None
            assert session.get(sp.SESSION_START_KEY)

    def test_login_stamps_the_start(self, app, user):
        with request_for(app, "/dataset"):
            sp.on_user_logged_in(None, user=model.User.get(user["id"]))
            assert session.get(sp.SESSION_START_KEY)

    def test_login_also_seeds_the_activity_stamp(self, app, user):
        # The idle clock must start at login, not at the second navigation:
        # the write on the first post-login request does not reliably reach the
        # Beaker cookie, so the login signal seeds it while the login request's
        # own session save persists it.
        with request_for(app, "/dataset"):
            sp.on_user_logged_in(None, user=model.User.get(user["id"]))
            assert session.get(sp.SESSION_KEY)

    def test_the_api_is_exempt(self, app, user):
        old = int(time.time()) - self._cap() - 1
        with request_for(app, "/api/3/action/status_show", user):
            session[sp.SESSION_START_KEY] = old
            assert sp.enforce_absolute_timeout() is None

    def test_anonymous_requests_are_untouched(self, app):
        with request_for(app, "/dataset"):
            assert sp.enforce_absolute_timeout() is None

    def test_the_cap_can_be_switched_off(self, app, user):
        with changed_config("ckanext.sse.session.max_session_hours", "0"):
            with request_for(app, "/dataset", user):
                session[sp.SESSION_START_KEY] = int(time.time()) - 100000
                assert sp.enforce_absolute_timeout() is None

    def test_the_cap_is_configurable(self, app, user):
        with changed_config("ckanext.sse.session.max_session_hours", "1"):
            with request_for(app, "/dataset", user):
                session[sp.SESSION_START_KEY] = int(time.time()) - 7200
                assert sp.enforce_absolute_timeout() is not None

    def test_a_broken_setting_falls_back_to_the_default(self):
        with changed_config("ckanext.sse.session.max_session_hours", "nope"):
            assert sp.max_session_seconds() == \
                sp.DEFAULT_MAX_SESSION_HOURS * 3600
