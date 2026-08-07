"""Tests for ckanext.sse.account_lifecycle (AC-2.3)."""

import datetime
import itertools

import pytest

import ckan.model as model
from ckan.model.meta import Session
from ckan.tests import factories
from ckan.tests.helpers import changed_config

from ckanext.sse import account_lifecycle as al

PASSWORD = "quixotic wobble lantern"


_serial = itertools.count()


def make_user(created_days_ago=90, active_days_ago=None, **kwargs):
    """A user with its creation and activity timestamps placed in the past."""
    kwargs.setdefault("email", "lifecycle-%s@example.com" % next(_serial))
    user = factories.User(password=PASSWORD, **kwargs)
    user_obj = model.User.get(user["id"])

    now = datetime.datetime.utcnow()
    user_obj.created = now - datetime.timedelta(days=created_days_ago)
    user_obj.last_active = (
        None if active_days_ago is None
        else now - datetime.timedelta(days=active_days_ago)
    )
    Session.commit()
    return user_obj


@pytest.mark.usefixtures("with_plugins", "sse_tables")
class TestEligibility:
    def test_an_account_idle_beyond_the_threshold_is_eligible(self):
        """AC-2.3 e: last logon greater than 45 days."""
        user = make_user(created_days_ago=90, active_days_ago=46)
        assert al.is_eligible(user) is True

    def test_an_account_used_recently_is_not(self):
        user = make_user(created_days_ago=90, active_days_ago=44)
        assert al.is_eligible(user) is False

    def test_a_new_account_is_not_eligible_however_idle(self):
        """AC-2.3 e: creation date greater than 30 days.

        The clause exists so an account issued but not yet used is not
        disabled before its holder has had a chance to use it.
        """
        user = make_user(created_days_ago=29, active_days_ago=None)
        assert al.is_eligible(user) is False

    def test_an_old_account_that_was_never_used_is_eligible(self):
        user = make_user(created_days_ago=90, active_days_ago=None)
        assert al.is_eligible(user) is True

    def test_a_disabled_account_is_left_alone(self):
        user = make_user(created_days_ago=90, active_days_ago=90)
        user.state = model.State.DELETED
        Session.commit()
        assert al.is_eligible(user) is False

    def test_sysadmins_are_exempt_by_default(self):
        """The equivalent of AC-2.3's "Admin Disablement" groups.

        A sweep that disables every administrator during a quiet month
        leaves nobody able to undo it.
        """
        user = make_user(created_days_ago=90, active_days_ago=90,
                         sysadmin=True)
        assert al.is_eligible(user) is False

        with changed_config("ckanext.sse.inactivity.exempt_sysadmins",
                            "false"):
            assert al.is_eligible(user) is True

    def test_named_accounts_can_be_exempted(self):
        user = make_user(created_days_ago=90, active_days_ago=90)
        with changed_config("ckanext.sse.inactivity.exempt_users",
                            user.name.upper()):
            assert al.is_eligible(user) is False

    def test_the_site_user_is_always_exempt(self):
        """It never signs in, and disabling it breaks the site."""
        user = make_user(created_days_ago=900, active_days_ago=900)
        with changed_config("ckan.site_id", user.name):
            assert al.is_eligible(user) is False

    def test_the_thresholds_are_configurable(self):
        user = make_user(created_days_ago=90, active_days_ago=20)
        assert al.is_eligible(user) is False
        assert al.is_eligible(user, idle=10) is True


@pytest.mark.usefixtures("with_plugins", "sse_tables")
class TestSweep:
    def test_eligible_accounts_are_disabled(self):
        stale = make_user(created_days_ago=90, active_days_ago=60)
        fresh = make_user(created_days_ago=90, active_days_ago=1)

        disabled = al.disable_inactive_users()

        assert [record["name"] for record in disabled] == [stale.name]
        Session.refresh(stale)
        Session.refresh(fresh)
        assert stale.state == model.State.DELETED
        assert fresh.state == model.State.ACTIVE

    def test_a_dry_run_changes_nothing(self):
        stale = make_user(created_days_ago=90, active_days_ago=60)

        disabled = al.disable_inactive_users(dry_run=True)

        assert [record["name"] for record in disabled] == [stale.name]
        Session.refresh(stale)
        assert stale.state == model.State.ACTIVE

    def test_the_sweep_is_idempotent(self):
        make_user(created_days_ago=90, active_days_ago=60)

        assert len(al.disable_inactive_users()) == 1
        assert al.disable_inactive_users() == []

    def test_the_report_carries_the_evidence(self):
        """AC-2.3's evidence requirement needs the numbers, not just names."""
        make_user(created_days_ago=90, active_days_ago=60)
        record = al.disable_inactive_users(dry_run=True)[0]
        assert record["idle_days"] == 60
        assert record["last_active"] is not None
        assert record["created"] is not None
