"""Tests for ckanext.sse.password_policy.

Every user here is created with an explicit password. ``factories.User``
defaults to ``faker.password()``, which is ten characters long and so fails
this policy -- a bare ``factories.User()`` raises ``ValidationError`` while
this plugin is enabled.

Run with::

    pytest ckanext/sse/tests/test_password_policy.py
"""

import datetime
from contextlib import contextmanager

import pytest
from flask_login import login_user
from passlib.hash import pbkdf2_sha512

import ckan.model as model
import ckan.plugins.toolkit as toolkit
from ckan.common import session
from ckan.model.meta import Session
from ckan.tests import factories
from ckan.tests.helpers import changed_config

from ckanext.sse import password_policy as pp
from ckanext.sse.model import UserPasswordHistory

STRONG = "Tr0mb0ne-Yak!79"
ALSO_STRONG = "Zither-Qu1ck!42"
THIRD_STRONG = "Wombat-Fl!ng62p"


EMAIL = "policy-test@example.com"


def make_user(password=STRONG, **kwargs):
    kwargs.setdefault("email", EMAIL)
    return factories.User(password=password, **kwargs)


def set_password(user, password):
    """Change a password the way the profile form and the API both do."""
    return toolkit.get_action("user_update")(
        {"ignore_auth": True, "user": user["name"]},
        {
            "id": user["id"],
            "name": user["name"],
            # ``user_show`` omits the email for anyone but the user themselves
            # or a sysadmin, and ``user_update`` requires it.
            "email": user.get("email") or EMAIL,
            "password": password,
        },
    )


@contextmanager
def request_for(app, url, user=None):
    """A request context for ``url``, optionally with ``user`` signed in.

    The rotation check is exercised directly rather than by fetching a page,
    because rendering one needs every extension this portal's templates refer
    to and the tests run with ``ckan.plugins = sse`` alone. The one place a
    real page is fetched is the redirect test, where nothing is rendered.

    ``beaker.session`` has to be seeded because CKAN's session interface reads
    the session straight out of the WSGI environ, where the beaker middleware
    normally puts it (``BeakerSessionInterface``). Without it Flask hands back
    a ``NullSession`` that raises on write, and neither ``login_user`` nor the
    expiry warning can store anything.
    """
    with app.flask_app.test_request_context(
            url, environ_overrides={"beaker.session": {}}):
        if user is not None:
            login_user(model.User.get(user["id"]))
        yield


def enforce_for(app, url, user=None):
    """What the rotation check does to a request for ``url``."""
    with request_for(app, url, user):
        return pp.enforce_rotation()


def backdate(user_id, days):
    """Age every recorded password by ``days``.

    All of them, not just the newest: ageing one row only changes which row is
    the newest, and the rotation window is measured from whichever that is.
    """
    for offset, row in enumerate(pp._history(user_id)):
        row.created_at = (
            datetime.datetime.utcnow()
            - datetime.timedelta(days=days + offset)
        )
    Session.commit()


# --------------------------------------------------------------------------
# Strength
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "password",
    [
        "Tr0mb0ne-Yak!79",
        "correct horse Battery staple",   # the "three random word" approach
        "wombat lantern rivet",           # lowercase, no digits, no symbols
        "Wombat-Fl!ng62p",
    ],
)
def test_accepts_strong_passwords(password):
    assert pp.check_strength(password) == []


@pytest.mark.parametrize(
    "password",
    [
        "Sh0rt!aB",            # under the minimum length
        "x" * 200 + "A1!",     # over the maximum length
        "Whaaaaat-Yak!79",     # five of the same character in a row
        "wxyz-Tr0mbone!7",     # four sequential letters
        "Trombone-123-Yak",    # three sequential digits
        "Password-Yak!79",     # a banned word, verbatim
        "P@ssw0rd-Yak!7",      # the same word behind substitutions
        "Monkey2026!!",        # a common password with characters bolted on
    ],
)
def test_rejects_weak_passwords(password):
    assert pp.check_strength(password) != []


def test_no_character_classes_are_demanded_by_default():
    """The standard asks for passphrases, so complexity rules are off.

    A rule demanding an uppercase, a digit and a symbol works directly
    against the "three random word" approach the standard recommends.
    """
    assert pp.check_strength("wombat lantern rivet") == []


@pytest.mark.ckan_config(
    "ckanext.sse.password.require_character_classes", "true")
def test_character_classes_can_be_demanded():
    assert pp.check_strength("wombat lantern rivet") != []
    assert pp.check_strength("Wombat-Fl!ng62p") == []


def test_rejects_a_password_containing_the_users_own_details():
    assert pp.check_strength(
        "Jbloggs-Tr0mbone!7", identifiers=["jbloggs", "joe@example.com"]
    ) != []


def test_a_common_word_inside_a_longer_passphrase_is_allowed():
    """The point of the whole-word list: it must not ban English."""
    assert pp.check_strength("MonkeySawTheSunset!9") == []


def test_generated_passwords_satisfy_the_policy():
    for _unused in range(25):
        assert pp.check_strength(pp.generate_password(),
                                 privileged=True) == []


def test_generated_passwords_meet_the_service_account_length():
    assert len(pp.generate_password()) >= pp.DEFAULT_SERVICE_ACCOUNT_LENGTH


def test_generated_passwords_differ():
    assert len({pp.generate_password() for _unused in range(10)}) == 10


def test_administration_accounts_need_a_longer_passphrase():
    """IA-5.1 g: 12 characters for users, 15 for administration accounts."""
    twelve = "wombat rivet"
    assert len(twelve) == 12
    assert pp.check_strength(twelve) == []
    assert pp.check_strength(twelve, privileged=True) != []
    assert pp.check_strength("wombat lantern rivet", privileged=True) == []


@pytest.mark.ckan_config("ckanext.sse.password.min_length", "16")
def test_min_length_is_configurable():
    assert pp.check_strength("Tr0mb0ne-Yak!79") != []
    assert pp.check_strength("Tr0mb0ne-Yak!79xyQ") == []


@pytest.mark.ckan_config("ckanext.sse.password.min_length", "not a number")
def test_a_broken_setting_falls_back_to_the_default():
    assert pp.min_length() == pp.DEFAULT_MIN_LENGTH


@pytest.mark.ckan_config("ckanext.sse.password.extra_blocklist", "wombat")
def test_extra_blocklist_words_are_banned():
    assert pp.check_strength("Wombat-Fl!ng62p") != []


def test_a_maintained_blocklist_file_is_read(tmp_path):
    """IA-5.1 a and b: the list has to be updatable without a release."""
    listing = tmp_path / "compromised.txt"
    listing.write_text("# a comment\nhippopotamus\n\n")
    with changed_config("ckanext.sse.password.blocklist_file", str(listing)):
        assert pp.check_strength("hippopotamus") != []
        assert pp.check_strength("hippopotamus rivet lantern") == []

        # Replacing the file is picked up without a restart.
        listing.write_text("# a comment\n")
        assert pp.check_strength("hippopotamus") == []


def test_policy_rules_are_described():
    rules = pp.policy_rules(privileged=False)
    assert any("12" in rule for rule in rules)
    assert any(str(pp.DEFAULT_EXPIRY_DAYS) in rule for rule in rules)
    assert any("passphrase" in rule for rule in rules)

    privileged = pp.policy_rules(privileged=True)
    assert any("15" in rule for rule in privileged)
    assert any(str(pp.DEFAULT_PRIVILEGED_EXPIRY_DAYS) in rule
               for rule in privileged)


@pytest.mark.parametrize(
    "password, expected",
    [
        ("abcd", True),        # four sequential letters
        ("abc", False),        # three is allowed
        ("123", True),         # three sequential digits is not
        ("4321", True),        # descending too
        ("12", False),
        ("ab12cd", False),
        ("Summer2024 rivet", False),
        ("Tr0mb0ne-Yak!79", False),
    ],
)
def test_sequence_detection(password, expected):
    assert pp._has_sequence(password) is expected


@pytest.mark.parametrize(
    "password, expected",
    [
        ("aaaa", False),       # four repeats is allowed
        ("aaaaa", True),       # five is not
        ("Whaaaat", False),
        ("Whaaaaat", True),
    ],
)
def test_repeat_detection(password, expected):
    assert pp._has_repeat(password) is expected


def test_incremental_variants_reconstruct_the_previous_password():
    variants = pp.incremental_variants("Welcome101")
    assert "Welcome100" in variants
    assert "Welcome102" in variants
    assert "Welcome" in variants          # the digits dropped entirely
    assert "Welcome101" not in variants   # itself is not a variant

    # The last run of digits anywhere, not only a trailing one.
    assert "Summer2023!" in pp.incremental_variants("Summer2024!")

    # Zero padding is preserved as well as dropped, since the width can change.
    assert "Welcome09" in pp.incremental_variants("Welcome10")

    assert pp.incremental_variants("no digits here") == []


def test_rehash_of_the_same_password_is_recognised():
    """A hash upgraded to current pbkdf2 parameters is not a new password."""
    old = pbkdf2_sha512.using(rounds=1000).hash(STRONG)
    new = pbkdf2_sha512.hash(STRONG)
    assert pp._looks_like_rehash(old, new) is True
    # Two hashes both at current parameters say nothing about the password, so
    # the safe reading is "changed".
    assert pp._looks_like_rehash(new, pbkdf2_sha512.hash(ALSO_STRONG)) is False


# --------------------------------------------------------------------------
# History and reuse
# --------------------------------------------------------------------------


@pytest.mark.usefixtures("with_plugins", "sse_tables")
class TestHistory:
    def test_a_weak_password_cannot_be_registered(self):
        with pytest.raises(toolkit.ValidationError):
            make_user(password="password123")

    def test_creating_a_user_records_their_first_password(self):
        user = make_user()
        rows = pp._history(user["id"])
        assert len(rows) == 1
        assert pbkdf2_sha512.verify(STRONG, rows[0].password_hash)

    def test_the_current_password_cannot_be_set_again(self):
        user = make_user()
        with pytest.raises(toolkit.ValidationError):
            set_password(user, STRONG)

    def test_a_previous_password_cannot_be_set_again(self):
        user = make_user()
        set_password(user, ALSO_STRONG)
        with pytest.raises(toolkit.ValidationError):
            set_password(user, STRONG)

    def test_a_change_is_recorded(self):
        user = make_user()
        set_password(user, ALSO_STRONG)
        rows = pp._history(user["id"])
        assert len(rows) == 2
        assert pbkdf2_sha512.verify(ALSO_STRONG, rows[0].password_hash)

    @pytest.mark.ckan_config("ckanext.sse.password.history_length", "2")
    def test_the_history_is_pruned_to_the_configured_length(self):
        user = make_user()
        for n in range(4):
            set_password(user, "Quixot%sc-Wobble!%s7" % (chr(98 + n), n))
        assert len(pp._history(user["id"])) == 2

    @pytest.mark.ckan_config("ckanext.sse.password.history_length", "1")
    def test_a_password_beyond_the_history_can_be_reused(self):
        user = make_user()
        set_password(user, ALSO_STRONG)
        set_password(user, THIRD_STRONG)
        # Only the newest is retained, so the original is forgotten.
        set_password(user, STRONG)
        assert pp._history(user["id"])[0].password_hash

    def test_an_out_of_band_change_is_reconciled(self):
        """``ckan user setpass`` writes the model directly."""
        user = make_user()
        user_obj = model.User.get(user["id"])
        original = pp._history(user["id"])[0].id

        user_obj.password = ALSO_STRONG
        user_obj.save()
        Session.commit()

        row = pp.sync_history(user_obj)
        assert row.id != original
        assert pp.is_reused(ALSO_STRONG, user_obj)

    def test_a_user_with_no_history_is_seeded_rather_than_locked_out(self):
        user = make_user()
        Session.query(UserPasswordHistory).filter_by(
            user_id=user["id"]).delete()
        Session.commit()

        user_obj = model.User.get(user["id"])
        row = pp.sync_history(user_obj)
        assert row is not None
        assert not pp.is_expired(user_obj)

    def test_the_last_eight_passwords_are_retained_by_default(self):
        """IA-5.1: "Not be the same as any of the last 8 passwords"."""
        user = make_user()
        for n in range(10):
            set_password(user, "quixotic wobble %s" % chr(98 + n))
        assert len(pp._history(user["id"])) == 8
        assert pp.history_length() == 8

    def test_a_password_cannot_be_bumped_by_a_number(self):
        """IA-5.1: not "changed incrementally, e.g. Welcome100, Welcome101"."""
        user = make_user(password="quixotic wobble 100")
        with pytest.raises(toolkit.ValidationError) as raised:
            set_password(user, "quixotic wobble 101")
        assert "number changed" in str(raised.value.error_dict)

    def test_an_unrelated_password_with_a_number_is_accepted(self):
        user = make_user(password="quixotic wobble 100")
        set_password(user, "lantern rivet 42")
        assert len(pp._history(user["id"])) == 2


# --------------------------------------------------------------------------
# Rotation
# --------------------------------------------------------------------------


@pytest.mark.usefixtures("with_plugins", "sse_tables")
class TestRotation:
    def test_a_fresh_password_is_not_expired(self):
        user_obj = model.User.get(make_user()["id"])
        assert pp.is_expired(user_obj) is False
        assert pp.days_until_expiry(user_obj) == pp.DEFAULT_EXPIRY_DAYS - 1

    def test_a_password_past_the_window_is_expired(self):
        """IA-5 f: 365 days for a non-privileged user."""
        user = make_user()
        backdate(user["id"], days=pp.DEFAULT_EXPIRY_DAYS - 1)
        assert pp.is_expired(model.User.get(user["id"])) is False
        backdate(user["id"], days=pp.DEFAULT_EXPIRY_DAYS + 1)
        assert pp.is_expired(model.User.get(user["id"])) is True

    def test_a_privileged_password_expires_sooner(self):
        """IA-5 f: 60 days for a privileged user."""
        user = make_user(sysadmin=True)
        user_obj = model.User.get(user["id"])
        assert pp.is_privileged(user_obj) is True

        backdate(user["id"], days=pp.DEFAULT_PRIVILEGED_EXPIRY_DAYS - 1)
        assert pp.is_expired(user_obj) is False
        backdate(user["id"], days=pp.DEFAULT_PRIVILEGED_EXPIRY_DAYS + 1)
        assert pp.is_expired(user_obj) is True

    @pytest.mark.ckan_config("ckanext.sse.password.expiry_days", "0")
    def test_rotation_can_be_switched_off(self):
        user = make_user()
        backdate(user["id"], days=5000)
        user_obj = model.User.get(user["id"])
        assert pp.days_until_expiry(user_obj) is None
        assert pp.is_expired(user_obj) is False

    def test_an_expired_password_blocks_a_page(self, app):
        user = make_user()
        backdate(user["id"], days=pp.DEFAULT_EXPIRY_DAYS + 30)
        response = app.get(
            "/dataset",
            extra_environ={"REMOTE_USER": user["name"]},
            follow_redirects=False,
        )
        assert response.status_code == 302
        assert "/user/edit/{}".format(user["name"]) in \
            response.headers["Location"]

    def test_an_expired_password_does_not_block_the_change_form(self, app):
        user = make_user()
        backdate(user["id"], days=pp.DEFAULT_EXPIRY_DAYS + 30)
        assert enforce_for(app, "/user/edit/" + user["name"], user) is None

    def test_an_expired_password_does_not_block_the_api(self, app):
        user = make_user()
        backdate(user["id"], days=pp.DEFAULT_EXPIRY_DAYS + 30)
        assert enforce_for(app, "/api/3/action/status_show", user) is None

    def test_an_expired_password_does_not_block_logout(self, app):
        user = make_user()
        backdate(user["id"], days=pp.DEFAULT_EXPIRY_DAYS + 30)
        assert enforce_for(app, "/user/_logout", user) is None

    def test_an_expired_password_does_not_block_a_password_reset(self, app):
        user = make_user()
        backdate(user["id"], days=pp.DEFAULT_EXPIRY_DAYS + 30)
        assert enforce_for(app, "/user/reset", user) is None

    def test_a_valid_password_is_not_blocked(self, app):
        user = make_user()
        assert enforce_for(app, "/dataset", user) is None

    def test_changing_the_password_lifts_the_block(self, app):
        user = make_user()
        backdate(user["id"], days=pp.DEFAULT_EXPIRY_DAYS + 30)
        set_password(user, ALSO_STRONG)
        assert enforce_for(app, "/dataset", user) is None

    def test_an_anonymous_request_is_untouched(self, app):
        assert enforce_for(app, "/dataset") is None

    def test_an_approaching_expiry_warns_once(self, app):
        user = make_user()
        backdate(user["id"], days=pp.DEFAULT_EXPIRY_DAYS - 3)
        with request_for(app, "/dataset", user):
            assert pp.enforce_rotation() is None
            assert session.get(pp._WARNED_SESSION_KEY)
            # Read the flashes out of the session rather than through
            # ``get_flashed_messages``, which caches its result for the rest
            # of the request and so cannot show a second flash arriving.
            assert len(session["_flashes"]) == 1
            assert "expires in" in session["_flashes"][0][1]

            # Same session, so the second look says nothing more.
            pp.enforce_rotation()
            assert len(session["_flashes"]) == 1
