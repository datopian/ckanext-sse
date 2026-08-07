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


def make_user(created_days_ago=90, active_days_ago=None, capacity="editor",
              **kwargs):
    """A dormant user, in scope for the sweep unless told otherwise.

    ``capacity`` puts the account in an organisation, since the sweep only
    looks at privileged accounts; pass ``None`` for a plain registered user.
    """
    kwargs.setdefault("email", "lifecycle-%s@example.com" % next(_serial))
    user = factories.User(password=PASSWORD, **kwargs)
    user_obj = model.User.get(user["id"])

    if capacity:
        add_to_organization(user_obj, capacity)

    now = datetime.datetime.utcnow()
    user_obj.created = now - datetime.timedelta(days=created_days_ago)
    user_obj.last_active = (
        None if active_days_ago is None
        else now - datetime.timedelta(days=active_days_ago)
    )
    Session.commit()
    return user_obj


def add_to_organization(user, capacity="editor"):
    """Put a user in an organisation without going through the action layer.

    ``factories.Organization`` runs ``organization_create``, which dictizes
    the new organisation through ``package_search`` -- and this extension's
    ``package_search`` needs the scheming dataset schema, which is not loaded
    under ``ckan.plugins = sse``. The rows are what the sweep queries anyway.
    """
    org = model.Group(name="org-%s" % next(_serial), title="Org",
                      type="organization", is_organization=True)
    org.state = model.State.ACTIVE
    Session.add(org)
    Session.flush()
    Session.add(model.Member(group=org, table_id=user.id, table_name="user",
                             capacity=capacity, state="active"))
    Session.commit()
    return org


def add_as_collaborator(user, capacity="editor"):
    """Make a user a collaborator on a dataset, again without the actions."""
    package = model.Package(name="pkg-%s" % next(_serial), type="dataset")
    package.state = model.State.ACTIVE
    Session.add(package)
    Session.flush()
    Session.add(model.PackageMember(
        package_id=package.id, user_id=user.id, capacity=capacity,
        modified=datetime.datetime.utcnow(),
    ))
    Session.commit()
    return package


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

    def test_a_dormant_sysadmin_is_eligible(self):
        """A sysadmin account is the most valuable one on the site."""
        user = make_user(created_days_ago=90, active_days_ago=90,
                         capacity=None, sysadmin=True)
        assert al.is_eligible(user) is True

    def test_sysadmins_can_be_exempted(self):
        """The knob for an emergency account that is meant to sit unused."""
        user = make_user(created_days_ago=90, active_days_ago=90,
                         capacity=None, sysadmin=True)
        with changed_config("ckanext.sse.inactivity.exempt_sysadmins",
                            "true"):
            assert al.is_eligible(user) is False

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
class TestScope:
    """Only accounts carrying privilege are swept."""

    def test_a_plain_registered_account_is_left_alone(self):
        """Read access to public data is what anonymous visitors have."""
        user = make_user(created_days_ago=90, active_days_ago=90,
                         capacity=None)
        assert al.is_privileged(user) is False
        assert al.is_eligible(user) is False

    @pytest.mark.parametrize("capacity", ["admin", "editor", "member"])
    def test_organisation_membership_puts_an_account_in_scope(self, capacity):
        user = make_user(created_days_ago=90, active_days_ago=90,
                         capacity=capacity)
        assert al.is_privileged(user) is True
        assert al.is_eligible(user) is True

    def test_a_sysadmin_is_in_scope_without_any_organisation(self):
        user = make_user(created_days_ago=90, active_days_ago=90,
                         capacity=None, sysadmin=True)
        assert al.is_privileged(user) is True

    def test_a_dataset_collaborator_is_in_scope(self):
        """An editor collaborator can change datasets without an org."""
        user = make_user(created_days_ago=90, active_days_ago=90,
                         capacity=None)
        add_as_collaborator(user)

        assert al.is_privileged(user) is True
        assert al.is_eligible(user) is True

    def test_collaborators_can_be_left_out(self):
        user = make_user(created_days_ago=90, active_days_ago=90,
                         capacity=None)
        add_as_collaborator(user)

        with changed_config(
                "ckanext.sse.inactivity.include_collaborators", "false"):
            assert al.is_privileged(user) is False

    def test_which_capacities_count_is_configurable(self):
        user = make_user(created_days_ago=90, active_days_ago=90,
                         capacity="member")
        with changed_config("ckanext.sse.inactivity.capacities",
                            "admin editor"):
            assert al.is_privileged(user) is False

    def test_the_scope_can_be_widened_to_every_account(self):
        user = make_user(created_days_ago=90, active_days_ago=90,
                         capacity=None)
        assert al.is_eligible(user) is False
        with changed_config("ckanext.sse.inactivity.privileged_only",
                            "false"):
            assert al.is_eligible(user) is True

    def test_the_sweep_skips_unprivileged_accounts(self):
        privileged = make_user(created_days_ago=90, active_days_ago=90,
                               capacity="editor")
        plain = make_user(created_days_ago=90, active_days_ago=90,
                          capacity=None)

        disabled = al.disable_inactive_users(dry_run=True)

        names = [record["name"] for record in disabled]
        assert privileged.name in names
        assert plain.name not in names


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
