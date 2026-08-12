"""Tests for ckanext.sse.login_throttle (AC-7).

These need a reachable Redis, since the lockout state lives there. The ini
used to run them must point ``ckan.redis.url`` at one; ``test-core.ini``
leaves it at ``localhost``, which is not where Redis is in the Docker
development environment.
"""

import pytest
from flask_login import user_logged_in

import ckan.model as model
import ckan.plugins.toolkit as toolkit
from ckan.lib.redis import connect_to_redis
from ckan.tests import factories

from ckanext.sse import login_throttle as lt

PASSWORD = "quixotic wobble lantern"
EMAIL = "throttle-test@example.com"


@pytest.fixture
def clean_redis():
    """The throttle state outlives a test, so clear it either side."""
    def _clear():
        redis = connect_to_redis()
        for pattern in ("sse:login:failures:*", "sse:login:lock:*"):
            keys = list(redis.scan_iter(match=pattern))
            if keys:
                redis.delete(*keys)

    _clear()
    yield
    _clear()


@pytest.fixture
def user():
    return factories.User(password=PASSWORD, email=EMAIL)


def login_context(app, login, method="POST"):
    """A request context that looks like a submission of the login form."""
    return app.flask_app.test_request_context(
        "/user/login",
        method=method,
        data={"login": login, "password": "wrong"},
        environ_overrides={"beaker.session": {}},
    )


@pytest.mark.usefixtures("with_plugins", "sse_tables", "clean_redis")
class TestThrottleKey:
    def test_a_username_and_an_email_share_one_budget(self, user):
        """Otherwise the limit is simply doubled by using the other form."""
        assert lt.throttle_key(user["name"]) == user["name"]
        assert lt.throttle_key(EMAIL) == user["name"]

    def test_case_does_not_multiply_the_budget(self):
        assert lt.throttle_key("NoSuchUser") == "nosuchuser"

    def test_an_unknown_login_is_still_counted(self):
        """Spraying invented names must not get an unlimited budget."""
        assert lt.throttle_key("no-such-account") == "no-such-account"

    def test_nothing_useful_is_not_a_key(self):
        assert lt.throttle_key("") is None
        assert lt.throttle_key("   ") is None
        assert lt.throttle_key(None) is None


@pytest.mark.usefixtures("with_plugins", "sse_tables", "clean_redis")
class TestLockout:
    def test_the_account_locks_on_the_sixth_attempt(self, user):
        """AC-7 a: "a limit of six consecutive invalid logon attempts"."""
        key = user["name"]
        for attempt in range(1, lt.DEFAULT_MAX_ATTEMPTS):
            lt.record_failure(key, model.User.get(key))
            assert lt.is_locked(key) is False, (
                "locked after %s attempts" % attempt)

        lt.record_failure(key, model.User.get(key))
        assert lt.is_locked(key) is True

    def test_the_lock_expires_on_its_own(self, user):
        """AC-7 b: locked "for 30 minutes"."""
        key = user["name"]
        for _unused in range(lt.DEFAULT_MAX_ATTEMPTS):
            lt.record_failure(key, model.User.get(key))

        remaining = lt.lock_seconds_remaining(key)
        assert 0 < remaining <= lt.DEFAULT_LOCKOUT_MINUTES * 60

    def test_an_administrator_can_release_the_lock(self, user):
        """AC-7 b: "or until released by an administrator"."""
        key = user["name"]
        for _unused in range(lt.DEFAULT_MAX_ATTEMPTS):
            lt.record_failure(key, model.User.get(key))
        assert lt.is_locked(key) is True

        assert lt.clear(key) is True
        assert lt.is_locked(key) is False
        assert lt.status(key)["failures"] == 0

    def test_a_successful_login_ends_the_run(self, user):
        """"Consecutive" means a success resets the count."""
        key = user["name"]
        for _unused in range(lt.DEFAULT_MAX_ATTEMPTS - 1):
            lt.record_failure(key, model.User.get(key))
        assert lt.status(key)["failures"] == lt.DEFAULT_MAX_ATTEMPTS - 1

        lt.on_user_logged_in(None, user=model.User.get(key))
        assert lt.status(key)["failures"] == 0

        # And the next failure starts from one again.
        lt.record_failure(key, model.User.get(key))
        assert lt.status(key)["failures"] == 1

    @pytest.mark.ckan_config("ckanext.sse.login.max_attempts", "2")
    def test_the_limit_is_configurable(self, user):
        key = user["name"]
        lt.record_failure(key, model.User.get(key))
        assert lt.is_locked(key) is False
        lt.record_failure(key, model.User.get(key))
        assert lt.is_locked(key) is True

    def test_an_unknown_account_can_be_locked_too(self):
        key = lt.throttle_key("no-such-account")
        for _unused in range(lt.DEFAULT_MAX_ATTEMPTS):
            lt.record_failure(key, None)
        assert lt.is_locked(key) is True


@pytest.mark.usefixtures("with_plugins", "sse_tables", "clean_redis")
class TestHooks:
    def test_a_failed_login_is_counted(self, app, user):
        with login_context(app, user["name"]):
            lt.on_failed_login(user["name"])
        assert lt.status(user["name"])["failures"] == 1

    def test_a_failed_password_change_is_not_a_logon_attempt(self, app, user):
        """``failed_login`` also fires for the profile form's old-password
        check, and mistyping that must not lock the account."""
        with app.flask_app.test_request_context(
                "/user/edit/{}".format(user["name"]), method="POST",
                environ_overrides={"beaker.session": {}}):
            lt.on_failed_login(user["name"])
        assert lt.status(user["name"])["failures"] == 0

    def test_a_locked_account_is_refused_before_the_view_runs(self, app, user):
        key = user["name"]
        for _unused in range(lt.DEFAULT_MAX_ATTEMPTS):
            lt.record_failure(key, model.User.get(key))

        with login_context(app, key):
            response = lt.check_login_lock()
        assert response is not None
        assert response.status_code == 302
        assert "/user/login" in response.headers["Location"]

    def test_an_unlocked_account_is_left_alone(self, app, user):
        with login_context(app, user["name"]):
            assert lt.check_login_lock() is None

    def test_a_locked_account_is_refused_by_email_too(self, app, user):
        key = user["name"]
        for _unused in range(lt.DEFAULT_MAX_ATTEMPTS):
            lt.record_failure(key, model.User.get(key))

        with login_context(app, EMAIL):
            assert lt.check_login_lock() is not None

    def test_other_requests_are_untouched(self, app, user):
        with app.flask_app.test_request_context(
                "/dataset", environ_overrides={"beaker.session": {}}):
            assert lt.check_login_lock() is None


@pytest.mark.usefixtures("with_plugins", "sse_tables", "clean_redis")
def test_a_locked_account_cannot_log_in_over_http(app, user):
    """The whole control, end to end, through CKAN's own login view."""
    key = user["name"]
    for _unused in range(lt.DEFAULT_MAX_ATTEMPTS):
        lt.record_failure(key, model.User.get(key))

    response = app.post(
        "/user/login",
        data={"login": key, "password": PASSWORD},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert "/user/login" in response.headers["Location"]

    # The correct password did not shorten the lockout either.
    assert lt.is_locked(key) is True


@pytest.mark.usefixtures("with_plugins", "sse_tables", "clean_redis")
def test_the_signal_subscriptions_are_registered():
    subscriptions = lt.get_subscriptions()
    assert lt.on_failed_login in subscriptions[toolkit.signals.failed_login]
    assert lt.on_user_logged_in in subscriptions[user_logged_in]
