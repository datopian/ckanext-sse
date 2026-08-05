"""Password strength, reuse and rotation policy.

Three separate controls, all driven from this module:

* **Strength** -- CKAN's own rule is "8 characters or longer" and nothing
  else. ``user_password_validator`` here replaces it. The replacement is
  picked up by *name*: ``ckan.logic.schema`` resolves its validators through
  ``logic.get_validator``, which lets ``IValidators`` implementations shadow
  core ones, so a single entry in ``get_validators()`` covers ``user_create``,
  ``user_update``, the registration form, the profile form and the
  forgotten-password reset in one go. Overriding the schemas instead would
  have meant chasing five of them.

  ``ckan/views/user.py`` keeps its own hardcoded 8-character check in
  ``PerformResetView._get_form_password``, which runs *before* the action.
  That is a floor, not a ceiling: the action still validates, so a weak
  password submitted to the reset form is still rejected -- just with the
  error rendered from ``error_dict`` rather than beside the field.

* **Reuse** -- every password a user has held is recorded in
  ``user_password_history`` and a candidate is verified against each of the
  retained hashes. pbkdf2 salts per hash, so a repeated password cannot be
  recognised by comparing hashes; it has to be verified one at a time, which
  is why the history length is bounded.

* **Rotation** -- once a password is older than the configured window the user
  is redirected to the profile form until they change it. Enforced from a
  ``before_app_request`` handler on the routeless blueprint at the bottom of
  this module, which Flask runs before dispatching any view and which
  short-circuits the request if it returns a response.

  ``IAuthenticator.identify`` looks like the natural hook and is not one.
  ``identify_user()`` stops calling authenticators as soon as one of them
  leaves a user identified (``ckan/views/__init__.py``), and
  ``ckanext-noanonaccess`` is ahead of this extension in ``ckan.plugins``, so
  for an authenticated user -- the only kind this check applies to --
  ``identify()`` here is never reached. Measured, not assumed: the redirect
  silently did nothing until this moved to a blueprint handler. CKAN registers
  its own ``before_request`` before any extension blueprint, so by the time
  this runs ``current_user`` is resolved.

Enforcement is deliberately limited to browser requests. The action API is
exempt: an API token is a separate credential with its own lifecycle, its
holder may be an integration whose owner never signs in to a page, and
answering a JSON call with a redirect to an HTML form breaks the client
rather than protecting anything.

When the password was last changed
----------------------------------

There is no such column on ``user``, and several code paths change a password
without going through an action at all -- ``ckan user setpass`` assigns
``user.password`` and commits. So the history table is *reconciled* against
the live hash whenever it is read: a live hash that is not the newest recorded
one is recorded, with the clock restarted.

That reconciliation is also what seeds the table. Nothing needs migrating and
no one is locked out on the day this ships: the first request each existing
user makes records their current hash and starts a full window for them.

The one case reconciliation could misread is CKAN's rehash-on-login. When a
stored hash predates the current passlib parameters, ``validate_password``
transparently re-hashes the *same* password at the new rounds and saves it, so
the hash changes without the password changing. Restarting the rotation clock
there would silently extend the window, so it is detected -- an old hash below
current pbkdf2 parameters replaced by one at them -- and the stored hash is
updated in place, keeping the original date. See ``_looks_like_rehash``.

Configuration (all optional)
----------------------------

============================================== ==========================
``ckanext.sse.password.min_length``            12
``ckanext.sse.password.max_length``            128
``ckanext.sse.password.history_length``        5 (0 disables the reuse check)
``ckanext.sse.password.expiry_days``           90 (0 disables rotation)
``ckanext.sse.password.warn_days``             14 (0 disables the warning)
``ckanext.sse.password.extra_blocklist``       extra banned words
============================================== ==========================
"""

import datetime
import logging
import re
import secrets
import string

from flask import Blueprint, g, has_request_context
from passlib.hash import pbkdf2_sha512

import ckan.model as core_model
import ckan.plugins.toolkit as toolkit
from ckan.common import session
from ckan.lib.navl.dictization_functions import Missing
from ckan.model.meta import Session

from ckanext.sse.model import UserPasswordHistory

log = logging.getLogger(__name__)

_ = toolkit._

DEFAULT_MIN_LENGTH = 12

# Not tidiness: the candidate is fed to pbkdf2 once per history entry plus
# once to store it, and pbkdf2 cost is linear in input length. Without a cap a
# multi-megabyte "password" is a cheap way to tie up a worker.
DEFAULT_MAX_LENGTH = 128

DEFAULT_HISTORY_LENGTH = 5
DEFAULT_EXPIRY_DAYS = 90
DEFAULT_WARN_DAYS = 14

# A run of this many identical characters is rejected, so "aaa" is out.
MAX_REPEAT = 3

# A run of this many consecutive codepoints is rejected, so "1234", "abcd" and
# "9876" are out.
MAX_SEQUENCE = 4

# Symbols used when generating a password. Quotes, backslashes and spaces are
# left out: generated passwords get passed through shells, JSON bodies and
# .ini files, and a quoting bug there is a lockout.
GENERATED_SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"

# Words that must not appear *anywhere* in the password, matched against the
# letters of the password with common character substitutions undone -- so
# "P@ssw0rd!2026" is caught by "password". Kept short and unambiguous on
# purpose: substring matching over a large word list rejects perfectly good
# passphrases, which pushes users towards the shortest thing that passes.
#
# The portal's own names are listed here rather than derived from
# ``ckan.site_title``, because a title is a sentence: "SSEN Distribution Data
# Portal" would ban "data" as a substring and take "metadata" and "database"
# with it. Add site-specific words through
# ``ckanext.sse.password.extra_blocklist``.
BANNED_SUBSTRINGS = """
password passwd letmein changeme
qwerty qwertz azerty asdfgh zxcvbn abcdef qazwsx
iloveyou trustno welcome secret
admin sysadmin guest ckan datopian ssen
"""

# Common passwords, matched against the password once reduced to its letters,
# and only when the word accounts for nearly all of them -- so "Monkey2026!"
# and "Monkey99x" are rejected but "MonkeySawTheSunset" is not. Matching these
# as substrings instead would ban ordinary English words from passphrases,
# which is where a passphrase's strength comes from.
BANNED_WHOLE = """
monkey dragon football baseball basketball soccer cricket rugby
superman batman starwars pokemon princess sunshine shadow master
ninja hunter freedom whatever computer internet samsung google apple
michael jennifer jordan thomas charlie robert daniel matthew ashley
buster harley hockey ranger george andrew tigger joshua cheese amanda
ginger hammer silver purple orange banana chicken flower matrix cookie
killer jessica pepper maggie mickey bailey hannah nicole lovely sophie
chocolate friends family please summer winter spring autumn
liverpool chelsea arsenal celtic rangers glasgow edinburgh aberdeen
dundee london england scotland scottish southern
energy portal dataset dataportal opendata electricity distribution
"""

# How many letters a password may have beyond a ``BANNED_WHOLE`` word before
# it stops counting as that password. Two, so "monkey" catches "monkeyx" and
# "xmonkeyy" -- the usual way of getting a rejected password past a checker --
# without catching a passphrase that happens to contain the word.
WHOLE_WORD_SLACK = 2

# Substitutions to undo before matching against the word lists. Only the
# unambiguous ones: mapping "6" to "g" or "2" to "z" mangles more passwords
# than it catches.
LEET_MAP = str.maketrans(
    {
        "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
        "@": "a", "$": "s", "!": "i", "|": "i", "+": "t", "(": "c",
    }
)

# Endpoints reachable while a password is expired. Everything else redirects
# to the profile form.
#
# The reset endpoints are here because a user who has forgotten the password
# they are being asked to replace has no other way through -- the profile form
# demands the old one. Logout is here so the block is not a trap. Static and
# asset endpoints are here so the page the user is sent to can render.
ALLOWED_WHILE_EXPIRED = frozenset(
    {
        "user.edit",
        "user.logout",
        "user.logged_out",
        "user.logged_out_page",
        "user.request_reset",
        "user.perform_reset",
        "static",
        "webassets.index",
        "_debug_toolbar.static",
        "util.internal_redirect",
        "util.redirect",
    }
)

# Where an expired user is sent.
CHANGE_PASSWORD_ENDPOINT = "user.edit"

# Request attribute holding this request's reconciled history row, so a page
# that consults the policy more than once still costs one query.
_LATEST_ATTR = "sse_password_latest"

# Session key recording which expiry the user has already been warned about,
# so the warning appears once per browser session rather than on every page.
_WARNED_SESSION_KEY = "sse_password_expiry_warned"


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------


def _int_config(key, default, minimum=0):
    """An int setting, normalised so a bad value cannot break a login."""
    raw = toolkit.config.get(key, default)
    try:
        value = toolkit.asint(raw)
    except (ValueError, TypeError):
        log.warning("Ignoring invalid %s %r, using %s", key, raw, default)
        return default
    return max(minimum, value)


def min_length():
    return _int_config("ckanext.sse.password.min_length",
                       DEFAULT_MIN_LENGTH, minimum=8)


def max_length():
    return max(
        min_length(),
        _int_config("ckanext.sse.password.max_length", DEFAULT_MAX_LENGTH,
                    minimum=8),
    )


def history_length():
    """How many previous passwords may not be reused. 0 disables the check."""
    return _int_config("ckanext.sse.password.history_length",
                       DEFAULT_HISTORY_LENGTH)


def expiry_days():
    """Rotation window in days. 0 disables rotation entirely."""
    return _int_config("ckanext.sse.password.expiry_days",
                       DEFAULT_EXPIRY_DAYS)


def warn_days():
    """How far ahead of expiry to warn. 0 disables the warning."""
    return _int_config("ckanext.sse.password.warn_days", DEFAULT_WARN_DAYS)


def _word_list(configured, builtin):
    words = re.split(r"[,\s]+", "{} {}".format(builtin, configured or "").strip())
    return {word.lower() for word in words if len(word) > 3}


def _banned_substrings():
    """Words banned anywhere in the password."""
    extra = toolkit.config.get("ckanext.sse.password.extra_blocklist", "")
    return _word_list(extra, BANNED_SUBSTRINGS)


def _banned_whole():
    return _word_list("", BANNED_WHOLE)


# --------------------------------------------------------------------------
# Strength
# --------------------------------------------------------------------------


def policy_rules():
    """The policy in words, for error messages and for the forms.

    Generated from the live configuration rather than written out twice: a
    hint that disagrees with the validator is worse than no hint.
    """
    rules = [
        _("be between {min} and {max} characters long").format(
            min=min_length(), max=max_length()
        ),
        _("contain an uppercase letter, a lowercase letter, a digit and a "
          "symbol"),
        _("not repeat the same character {n} or more times in a row").format(
            n=MAX_REPEAT
        ),
        _("not contain {n} or more sequential characters, such as 1234 or "
          "abcd").format(n=MAX_SEQUENCE),
        _("not be based on a common password, your username, your full name "
          "or your email address"),
    ]
    if history_length():
        rules.append(
            _("not be one of your {n} previous passwords").format(
                n=history_length()
            )
        )
    if expiry_days():
        rules.append(
            _("be changed at least every {n} days").format(n=expiry_days())
        )
    return rules


def _normalise(password, undo_substitutions):
    """The password reduced to letters, optionally with leetspeak undone."""
    text = password.lower()
    if undo_substitutions:
        text = text.translate(LEET_MAP)
    return "".join(char for char in text if char.isalpha())


def _has_repeat(password):
    return re.search(r"(.)\1{%d,}" % (MAX_REPEAT - 1), password) is not None


def _has_sequence(password):
    """Whether the password contains a run of consecutive codepoints.

    Catches ``1234`` and ``abcd`` in either direction. Codepoint arithmetic
    rather than a keyboard map: ``qwerty`` and friends are handled by the word
    list, and the point here is the numeric and alphabetic runs people reach
    for to satisfy a character-class rule.
    """
    run = 1
    step = 0
    for previous, current in zip(password, password[1:]):
        delta = ord(current) - ord(previous)
        if delta in (1, -1) and (step == 0 or delta == step):
            step = delta
            run += 1
            if run >= MAX_SEQUENCE:
                return True
        else:
            step = delta if delta in (1, -1) else 0
            run = 2 if step else 1
    return False


def _identifier_words(*values):
    """Words from a user's identity worth banning from their password.

    The email is split on its punctuation as well, so ``joe.bloggs@sse.com``
    contributes ``joe``, ``bloggs`` and ``sse`` -- the local part as a whole is
    rarely what someone types.
    """
    words = set()
    for value in values:
        if not value or not isinstance(value, str):
            continue
        for word in re.split(r"[^A-Za-z0-9]+", value.lower()):
            if len(word) > 3:
                words.add(word)
    return words


def check_strength(password, identifiers=()):
    """Every way ``password`` fails the policy, as a list of phrases.

    Phrases, not sentences: the caller joins them into one message because
    CKAN's ``error_summary`` only ever renders the first error per field, so
    reporting the failures separately would hide all but one of them.
    """
    if not isinstance(password, str):
        return [_("be a string")]

    failures = []
    if len(password) < min_length():
        failures.append(
            _("be at least {n} characters long").format(n=min_length())
        )
    if len(password) > max_length():
        failures.append(
            _("be no more than {n} characters long").format(n=max_length())
        )

    missing = []
    if not any(char.islower() for char in password):
        missing.append(_("a lowercase letter"))
    if not any(char.isupper() for char in password):
        missing.append(_("an uppercase letter"))
    if not any(char.isdigit() for char in password):
        missing.append(_("a digit"))
    # Anything that is not a letter or a digit counts, including a space, so
    # passphrases are not pushed towards punctuation soup.
    if not any(not char.isalnum() for char in password):
        missing.append(_("a symbol"))
    if missing:
        failures.append(_("contain {}").format(", ".join(missing)))

    if _has_repeat(password):
        failures.append(
            _("not repeat the same character {n} or more times in a "
              "row").format(n=MAX_REPEAT)
        )
    if _has_sequence(password):
        failures.append(
            _("not contain {n} or more sequential characters").format(
                n=MAX_SEQUENCE
            )
        )

    # Both forms are checked: the plain one catches "Password123", the
    # substituted one catches "P@ssw0rd". Checking only the substituted form
    # would miss words whose letters the substitutions rewrite.
    forms = {_normalise(password, False), _normalise(password, True)}
    if any(word in form
           for form in forms
           for word in _banned_substrings()):
        failures.append(_("not be based on a common or obvious password"))
    elif any(word in form and len(form) - len(word) <= WHOLE_WORD_SLACK
             for form in forms
             for word in _banned_whole()):
        failures.append(_("not be a commonly used password"))

    lowered = password.lower()
    if any(word in lowered for word in _identifier_words(*identifiers)):
        failures.append(
            _("not contain your username, name or email address")
        )

    return failures


def generate_password(length=None):
    """A random password that satisfies this policy.

    ``secrets`` rather than ``random``: this produces a real credential, and
    ``random`` is a Mersenne Twister whose output is recoverable from a
    handful of samples.

    Candidates are rejected by ``check_strength`` rather than assembled to
    satisfy each rule, so the generator cannot drift away from the policy --
    if a rule is added, this keeps producing valid passwords without being
    touched.
    """
    length = max(length or min_length() + 8, min_length())
    length = min(length, max_length())
    alphabet = string.ascii_letters + string.digits + GENERATED_SYMBOLS
    while True:
        candidate = "".join(secrets.choice(alphabet) for _unused in range(length))
        if not check_strength(candidate):
            return candidate


# --------------------------------------------------------------------------
# History
# --------------------------------------------------------------------------


def _history(user_id, limit=None):
    """Recorded hashes for a user, newest first."""
    query = (
        Session.query(UserPasswordHistory)
        .filter(UserPasswordHistory.user_id == user_id)
        # id as a tiebreaker: two rows written in the same transaction share a
        # timestamp, and an unstable order would make pruning arbitrary.
        .order_by(
            UserPasswordHistory.created_at.desc(),
            UserPasswordHistory.id.desc(),
        )
    )
    if limit:
        query = query.limit(limit)
    return query.all()


def _looks_like_rehash(old_hash, new_hash):
    """Whether ``new_hash`` is CKAN re-hashing the same password.

    ``User.validate_password`` upgrades a stored hash whose rounds or salt
    size are below passlib's current defaults, which changes the hash without
    the password changing. Recognised by exactly that: the hash we had was
    below current parameters and the one we see now is not.

    Deliberately narrow. Anything it is unsure about is treated as a real
    password change, which restarts the rotation clock -- asking someone to
    change their password sooner than necessary is the safe way to be wrong.
    """
    try:
        if not (pbkdf2_sha512.identify(old_hash)
                and pbkdf2_sha512.identify(new_hash)):
            return False
        old = pbkdf2_sha512.from_string(old_hash)
        new = pbkdf2_sha512.from_string(new_hash)
    except Exception:
        return False

    was_below_defaults = (
        old.rounds < pbkdf2_sha512.default_rounds
        or len(old.salt) < pbkdf2_sha512.default_salt_size
    )
    now_at_defaults = (
        new.rounds >= pbkdf2_sha512.default_rounds
        and len(new.salt) >= pbkdf2_sha512.default_salt_size
    )
    return was_below_defaults and now_at_defaults


def _prune(user_id):
    """Drop rows past the retained history length.

    The retained hashes are old credentials, so keeping more of them than the
    reuse check consults is a liability rather than an archive. One row is
    always kept whatever the setting, because the rotation window is measured
    from it.
    """
    keep = max(1, history_length())
    for row in _history(user_id)[keep:]:
        Session.delete(row)


def record_password(user_id, password_hash, when=None, commit=True):
    """Record a hash as this user's current password."""
    row = UserPasswordHistory(
        user_id=user_id,
        password_hash=password_hash,
        created_at=when or datetime.datetime.utcnow(),
    )
    Session.add(row)
    # CKAN's session is ``autoflush=False``, so without this the new row is
    # invisible to the query ``_prune`` runs and the history creeps one row
    # past the configured length.
    Session.flush()
    _prune(user_id)
    if commit:
        Session.commit()
    return row


def sync_history(user):
    """Reconcile the history against the live hash and return the newest row.

    Returns ``None`` only for a user with no usable password hash at all --
    an invited account that has never set one, for instance -- which has
    nothing to rotate.
    """
    if user is None or not getattr(user, "password", None):
        return None

    rows = _history(user.id, limit=1)
    latest = rows[0] if rows else None

    if latest is None:
        # First time we have seen this user. Their password is however old it
        # is, but there is no record of when it was set, so the window starts
        # now: locking every existing user out on the day this ships is not a
        # security improvement.
        return record_password(user.id, user.password)

    if latest.password_hash == user.password:
        return latest

    if _looks_like_rehash(latest.password_hash, user.password):
        # Same password, stronger storage. Keep the date.
        latest.password_hash = user.password
        Session.commit()
        return latest

    # Changed by something that does not go through the actions --
    # ``ckan user setpass``, or a direct write. Treat it as a change.
    return record_password(user.id, user.password)


def latest_change(user):
    """``sync_history`` memoised for the duration of the request."""
    if not has_request_context():
        return sync_history(user)
    cached = getattr(g, _LATEST_ATTR, False)
    if cached is not False:
        return cached
    latest = sync_history(user)
    setattr(g, _LATEST_ATTR, latest)
    return latest


def is_reused(password, user):
    """Whether ``password`` is the user's current or a recent password.

    The live hash is always checked, even when the history is switched off:
    "change your password" that accepts the same password back is not a
    change. Each check is a full pbkdf2 verification, which is why the number
    of them is bounded by ``history_length``.
    """
    if user is None:
        return False

    hashes = [getattr(user, "password", None)]
    if history_length():
        hashes += [row.password_hash for row in _history(user.id,
                                                        history_length())]

    for stored in hashes:
        if not stored:
            continue
        try:
            # Legacy sha1 hashes (CKAN < 2.0) are not pbkdf2 and make verify
            # raise. They belong to passwords nobody can still be reusing
            # deliberately, so skipping them is no loss.
            if not pbkdf2_sha512.identify(stored):
                continue
            if pbkdf2_sha512.verify(password, stored):
                return True
        except (ValueError, TypeError):
            continue
    return False


# --------------------------------------------------------------------------
# Validator
# --------------------------------------------------------------------------


def _target_user(data, context):
    """The user whose password is being set, if they already exist.

    ``user_update`` puts the row in the context before validating, which is
    the case that matters -- it is the only one where there is a history to
    check against. The lookup by ``id``/``name`` covers callers that build
    their own context, and returns ``None`` during ``user_create``.
    """
    user_obj = context.get("user_obj")
    if user_obj is not None:
        return user_obj
    for field in ("id", "name"):
        value = data.get((field,))
        if value and not isinstance(value, Missing):
            user = core_model.User.get(value)
            if user is not None:
                return user
    return None


def user_password_validator(key, data, errors, context):
    """Replaces CKAN's 8-character check. Registered by name.

    Errors are appended under ``('password',)`` regardless of which field is
    being validated, matching what core does: the form templates read
    ``errors.password1`` for the inline message but the summary is keyed on
    ``password``, and splitting the two would put the message nowhere on the
    registration form.
    """
    value = data[key]

    if isinstance(value, Missing) or value is None or value == "":
        # Absence is other validators' business: ``user_password_not_empty``
        # on create, ``ignore_missing`` on update.
        return

    if not isinstance(value, str):
        errors[("password",)].append(_("Passwords must be strings"))
        return

    user = _target_user(data, context)
    identifiers = [
        data.get(("name",)),
        data.get(("email",)),
        data.get(("fullname",)),
    ]
    if user is not None:
        identifiers += [user.name, user.email, user.fullname]
    identifiers = [
        value_ for value_ in identifiers
        if isinstance(value_, str) and value_
    ]

    failures = check_strength(value, identifiers)
    if failures:
        errors[("password",)].append(
            _("Your password must {}.").format("; ".join(failures))
        )
        # Stop here rather than also running the reuse check: a password that
        # fails the policy is being rejected either way, and the reuse check
        # costs a pbkdf2 verification per stored hash.
        return

    if is_reused(value, user):
        errors[("password",)].append(
            _("You have used this password before. Please choose a password "
              "you have not used on this account.")
        )


# --------------------------------------------------------------------------
# Recording changes made through the actions
# --------------------------------------------------------------------------


def _live_hash(ident):
    if not ident:
        return None
    user = core_model.User.get(ident)
    # A plain str, so it survives the update that is about to happen to the
    # row it came from.
    return user.password if user is not None else None


def _record_if_changed(ident, before, context):
    try:
        after = _live_hash(ident)
        if not after or after == before:
            return
        user = core_model.User.get(ident)
        # ``defer_commit`` means the caller owns the transaction: adding to it
        # is fine, committing it is not.
        row = record_password(user.id, after,
                              commit=not context.get("defer_commit"))
        if has_request_context():
            # The memoised row for this request is now stale, and the same
            # request goes on to render a page.
            setattr(g, _LATEST_ATTR, row)
    except Exception:
        # A password that changed but went unrecorded costs the user an early
        # rotation prompt. Failing the change itself would cost them the
        # account.
        log.exception("Failed to record password change for %s", ident)


@toolkit.chained_action
def user_create(up_func, context, data_dict):
    """Records the password a new account starts with.

    Without this the account's first history row would be written by
    ``sync_history`` on its first request, dating the password from then
    rather than from creation.
    """
    result = up_func(context, data_dict)
    _record_if_changed(result.get("id") or result.get("name"), None, context)
    return result


@toolkit.chained_action
def user_update(up_func, context, data_dict):
    """Records a password change made through the API, forms or reset flow.

    Detected by the hash changing rather than by ``password`` appearing in the
    payload: a sysadmin importing an account supplies ``password_hash``
    directly, and CKAN's own reset flow rebuilds the whole user dict.
    """
    before = _live_hash(data_dict.get("id"))
    result = up_func(context, data_dict)
    _record_if_changed(result.get("id") or data_dict.get("id"), before,
                       context)
    return result


# --------------------------------------------------------------------------
# Rotation
# --------------------------------------------------------------------------


def expires_at(user):
    """When this user's password expires, or ``None`` if it cannot."""
    days = expiry_days()
    if not days:
        return None
    latest = latest_change(user)
    if latest is None:
        return None
    return latest.created_at + datetime.timedelta(days=days)


def days_until_expiry(user):
    """Days left, negative once expired, or ``None`` if rotation is off.

    ``timedelta.days`` floors, which is what is wanted at both ends: a
    password with 12 hours left reports 0 -- "expires today" -- and one that
    expired an hour ago reports -1 rather than 0, so a single ``< 0`` test
    means expired.
    """
    expiry = expires_at(user)
    if expiry is None:
        return None
    return (expiry - datetime.datetime.utcnow()).days


def is_expired(user):
    remaining = days_until_expiry(user)
    return remaining is not None and remaining < 0


def enforce_rotation():
    """Redirect to the profile form while the user's password is expired.

    Returns ``None`` to let the request through.

    Nothing here may raise: this runs before every view, so an error in the
    policy would take the whole site down rather than one page.
    """
    try:
        return _enforce_rotation()
    except Exception:
        log.exception("Password rotation check failed; allowing the request")
        return None


def _enforce_rotation():
    if not has_request_context():
        return None
    if not expiry_days() and not warn_days():
        return None

    user = toolkit.current_user
    if user is None or getattr(user, "is_anonymous", True):
        return None
    # A pending invitee is mid-way through setting their first password and a
    # deleted account is on its way out; neither has a rotation to enforce.
    if getattr(user, "state", None) != "active":
        return None

    # The action API is exempt -- see the module docstring.
    if toolkit.request.path.startswith("/api/"):
        return None

    endpoint = toolkit.request.endpoint or ""
    blueprint = endpoint.split(".")[0]
    if endpoint in ALLOWED_WHILE_EXPIRED or blueprint in ("static",
                                                          "webassets"):
        return None

    remaining = days_until_expiry(user)
    if remaining is None:
        return None

    if remaining >= 0:
        _warn_if_expiring(user, remaining)
        return None

    # The rules themselves are on the page this redirects to, so the message
    # says why rather than repeating all of them.
    toolkit.h.flash_error(
        _("Your password is more than {days} days old. Choose a new one "
          "before continuing.").format(days=expiry_days())
    )
    return toolkit.redirect_to(CHANGE_PASSWORD_ENDPOINT, id=user.name)


def _warn_if_expiring(user, remaining):
    """Flash a warning as expiry approaches, once per browser session.

    Once per session rather than once per page: a banner on every page for a
    fortnight trains people to ignore banners.
    """
    window = warn_days()
    if not window or remaining > window:
        return

    expiry = expires_at(user)
    marker = expiry.date().isoformat() if expiry else str(remaining)
    try:
        if session.get(_WARNED_SESSION_KEY) == marker:
            return
        session[_WARNED_SESSION_KEY] = marker
    except Exception:
        # No usable session (an unsigned-cookie edge case): warning once is
        # still better than not warning.
        log.debug("Could not record password expiry warning in the session")

    if remaining == 0:
        message = _("Your password expires today. Change it to avoid losing "
                    "access.")
    else:
        message = _("Your password expires in {days} day(s). You will not be "
                    "able to use the site until you change it.").format(
                        days=remaining)
    toolkit.h.flash_notice(message)


# --------------------------------------------------------------------------
# Blueprint
# --------------------------------------------------------------------------

# Carries no routes. It exists only to hang the rotation check off
# ``before_app_request``, which is the one hook that runs before every view
# regardless of which extension owns the view or where this plugin sits in
# ``ckan.plugins``.
blueprint = Blueprint("sse_password_policy", __name__)


@blueprint.before_app_request
def check_password_rotation():
    return enforce_rotation()
