"""Password strength, reuse and rotation policy.

Implements SSE's *Standard for Identification and Authentication* IA-5 and
IA-5.1 as far as a CKAN portal can. Where the standard is written for Active
Directory the nearest portal equivalent is used, and where a requirement is
organisational rather than technical it is called out below rather than
quietly dropped.

IA-5.1, passphrase requirements, and where each one lives:

===================================================== ======================
12 characters or more, 15 for administration accounts ``check_strength``
Not on a list of common/expected/compromised passwords ``_blocklist``
Not contain any part of the username                  ``check_strength``
Not be a single dictionary word                       ``_blocklist`` (partial)
Not more than 4 repeating characters or digits        ``_has_repeat``
No ascending or descending number sequences           ``_has_sequence``
Not changed incrementally (Welcome100, Welcome101)    ``is_incremental``
Not the same as any of the last 8 passwords           ``is_reused``
New password on account recovery                      CKAN's reset flow
Stored with an approved salted hash                   CKAN's pbkdf2-sha512
===================================================== ======================

IA-5 f, rotation: 365 days for non-privileged users, 60 for privileged ones.
"Privileged" is read as a CKAN sysadmin; organisation admins are not system
administrators and are treated as ordinary users.

Deliberately *not* enforced here, because nothing in a CKAN extension can:
passwords transmitted only under TLS (IA-5.1 c, an ingress concern); admin
accounts not sharing a password with the holder's AD account (f); passphrases
not reused outside SSE. Note also that the standard prefers passphrases and
the "three random word" approach, so there is no character-class requirement
-- demanding an uppercase, a digit and a symbol would push users away from the
thing the standard asks for. ``ckanext.sse.password.require_character_classes``
turns one on for a deployment that wants it.

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

===================================================== ======================
``ckanext.sse.password.min_length``                   12
``ckanext.sse.password.privileged_min_length``        15
``ckanext.sse.password.max_length``                   128
``ckanext.sse.password.history_length``               8 (0: current only)
``ckanext.sse.password.expiry_days``                  365 (0 disables)
``ckanext.sse.password.privileged_expiry_days``       60 (0 disables)
``ckanext.sse.password.warn_days``                    14 (0 disables)
``ckanext.sse.password.max_repeat``                   4
``ckanext.sse.password.max_digit_sequence``           2
``ckanext.sse.password.max_letter_sequence``          3
``ckanext.sse.password.require_character_classes``    false
``ckanext.sse.password.bundled_blocklist``            true (ship NCSC top 100k)
``ckanext.sse.password.blocklist_files``              paths, space/comma sep.
``ckanext.sse.password.blocklist_file``               path (legacy, one file)
``ckanext.sse.password.extra_blocklist``              extra banned words
``ckanext.sse.password.hibp_check``                   false (opt-in HIBP)
===================================================== ======================
"""

import datetime
import hashlib
import logging
import os
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

# IA-5.1 g: "passphrases (12 characters or more)", and "Administration
# accounts passphrases should be minimum of 15 characters".
DEFAULT_MIN_LENGTH = 12
DEFAULT_PRIVILEGED_MIN_LENGTH = 15

# Not tidiness: the candidate is fed to pbkdf2 once per history entry plus
# once to store it, and pbkdf2 cost is linear in input length. Without a cap a
# multi-megabyte "password" is a cheap way to tie up a worker.
DEFAULT_MAX_LENGTH = 128

# IA-5.1: "Not be the same as any of the last 8 passwords".
DEFAULT_HISTORY_LENGTH = 8

# IA-5 f: 365 days for non-privileged users, 60 for privileged ones.
DEFAULT_EXPIRY_DAYS = 365
DEFAULT_PRIVILEGED_EXPIRY_DAYS = 60

DEFAULT_WARN_DAYS = 14

# IA-5.1: "Not have more than 4 repeating characters or digits", so a run of
# five is the first one rejected.
DEFAULT_MAX_REPEAT = 4

# IA-5.1: "Not contain ascending or descending number sequences". No length is
# given, so three is taken as the shortest run that is recognisably a sequence
# -- two consecutive digits happen by accident in any date.
DEFAULT_MAX_DIGIT_SEQUENCE = 2

# The standard names number sequences only. Letter runs are held to four
# because "abcd" is the same idea and costs nothing to catch.
DEFAULT_MAX_LETTER_SEQUENCE = 3

# How far either side of the number in a password to look when deciding
# whether it is the previous password with the number bumped.
DEFAULT_INCREMENT_WINDOW = 3

# IA-5.1 service-account passphrase lengths: 20 for a service account, 25 for
# an extended-privilege one. CKAN has no service accounts as such, but the
# accounts the frontend creates for itself are the nearest thing, and their
# passwords are generated rather than typed -- so length is free, and we take
# the highest bar (25).
DEFAULT_SERVICE_ACCOUNT_LENGTH = 25

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

# Blocklist files, cached per path on (mtime, size). Module level rather than
# per-request: the files are the same for every worker and rereading a
# compromised-password corpus on each password change would be wasteful.
_BLOCKLIST_CACHE = {}

# A common-passwords list shipped with the extension (NCSC top 100k, from
# SecLists, MIT-licensed), so the "not a commonly used password" rule works out
# of the box without any deployment configuration. Turn it off with
# ``ckanext.sse.password.bundled_blocklist = false``; add more (a larger
# corpus, a dictionary) through ``ckanext.sse.password.blocklist_files``.
_BUNDLED_BLOCKLIST = os.path.join(
    os.path.dirname(__file__), "data", "common-passwords.txt")


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


def is_privileged(user):
    """Whether the standard's "administration account" rules apply.

    A CKAN sysadmin. Organisation admins administer a publisher's datasets,
    not the system, so they are held to the ordinary user rules.
    """
    return bool(user is not None and getattr(user, "sysadmin", False))


def min_length(privileged=False):
    if privileged:
        return max(
            _int_config("ckanext.sse.password.privileged_min_length",
                        DEFAULT_PRIVILEGED_MIN_LENGTH, minimum=8),
            _int_config("ckanext.sse.password.min_length",
                        DEFAULT_MIN_LENGTH, minimum=8),
        )
    return _int_config("ckanext.sse.password.min_length",
                       DEFAULT_MIN_LENGTH, minimum=8)


def max_length():
    return max(
        min_length(privileged=True),
        _int_config("ckanext.sse.password.max_length", DEFAULT_MAX_LENGTH,
                    minimum=8),
    )


def history_length():
    """How many previous passwords may not be reused. 0 disables the check."""
    return _int_config("ckanext.sse.password.history_length",
                       DEFAULT_HISTORY_LENGTH)


def expiry_days(privileged=False):
    """Rotation window in days. 0 disables rotation entirely."""
    if privileged:
        return _int_config("ckanext.sse.password.privileged_expiry_days",
                           DEFAULT_PRIVILEGED_EXPIRY_DAYS)
    return _int_config("ckanext.sse.password.expiry_days",
                       DEFAULT_EXPIRY_DAYS)


def warn_days():
    """How far ahead of expiry to warn. 0 disables the warning."""
    return _int_config("ckanext.sse.password.warn_days", DEFAULT_WARN_DAYS)


def max_repeat():
    """Longest run of one repeated character that is still allowed."""
    return _int_config("ckanext.sse.password.max_repeat",
                       DEFAULT_MAX_REPEAT, minimum=1)


def max_digit_sequence():
    """Longest run of consecutive digits that is still allowed."""
    return _int_config("ckanext.sse.password.max_digit_sequence",
                       DEFAULT_MAX_DIGIT_SEQUENCE, minimum=1)


def max_letter_sequence():
    """Longest run of consecutive letters that is still allowed."""
    return _int_config("ckanext.sse.password.max_letter_sequence",
                       DEFAULT_MAX_LETTER_SEQUENCE, minimum=1)


def require_character_classes():
    """Whether to demand upper, lower, digit and symbol.

    Off by default: the standard asks for passphrases and the "three random
    word" approach, and a character-class rule works against both.
    """
    return toolkit.asbool(
        toolkit.config.get("ckanext.sse.password.require_character_classes",
                           False)
    )


def _word_list(configured, builtin):
    words = re.split(r"[,\s]+", "{} {}".format(builtin, configured or "").strip())
    return {word.lower() for word in words if len(word) > 3}


def _blocklist_paths():
    """Every blocklist file to load, in order.

    IA-5.1 a and b call for a list of common, expected and compromised
    passwords that is "updated continually", which a list baked into this
    module cannot be. So the extension ships a sensible default (the NCSC top
    100k) and takes any number of further files -- a compromised-password
    corpus, a dictionary, both -- through
    ``ckanext.sse.password.blocklist_files`` (space- or comma-separated). The
    legacy single ``blocklist_file`` is still honoured.
    """
    paths = []
    if toolkit.asbool(
            toolkit.config.get("ckanext.sse.password.bundled_blocklist", True)):
        paths.append(_BUNDLED_BLOCKLIST)

    configured = "{} {}".format(
        toolkit.config.get("ckanext.sse.password.blocklist_files", "") or "",
        toolkit.config.get("ckanext.sse.password.blocklist_file", "") or "",
    )
    for path in re.split(r"[,\s]+", configured.strip()):
        if path and path not in paths:
            paths.append(path)
    return paths


def _read_blocklist_file(path):
    """One blocklist file's words, cached per path on (mtime, size).

    A replaced file is picked up without a restart; an unchanged one is not
    re-read on every password change.
    """
    try:
        stat = os.stat(path)
        stamp = (stat.st_mtime, stat.st_size)
    except OSError:
        log.warning("Cannot read password blocklist %r", path)
        return frozenset()

    cached = _BLOCKLIST_CACHE.get(path)
    if cached and cached[0] == stamp:
        return cached[1]

    try:
        with open(path, encoding="utf-8", errors="ignore") as handle:
            words = frozenset(
                line.strip().lower() for line in handle
                if len(line.strip()) > 3 and not line.startswith("#")
            )
    except OSError:
        log.warning("Cannot read password blocklist %r", path)
        return frozenset()

    _BLOCKLIST_CACHE[path] = (stamp, words)
    log.info("Loaded %s password blocklist entries from %s", len(words), path)
    return words


def _blocklist_file_words():
    """The union of every configured/bundled blocklist file."""
    words = set()
    for path in _blocklist_paths():
        words |= _read_blocklist_file(path)
    return words


def hibp_check():
    """Whether to check candidates against Have I Been Pwned (opt-in).

    Off by default: it is an outbound call per password change and needs
    network egress. The bundled/​configured word lists cover the offline case;
    this adds the "updated continually" compromised-password corpus (IA-5.1 a)
    without shipping gigabytes of hashes.
    """
    return toolkit.asbool(
        toolkit.config.get("ckanext.sse.password.hibp_check", False))


def _is_pwned(password):
    """Whether ``password`` appears in Have I Been Pwned.

    Uses the k-anonymity range API -- only the first five SHA-1 hex characters
    leave the server, never the password. Fails open: an HIBP or network error
    must not block a legitimate password change.
    """
    try:
        import requests

        digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = digest[:5], digest[5:]
        resp = requests.get(
            "https://api.pwnedpasswords.com/range/" + prefix,
            timeout=3,
            headers={"Add-Padding": "true"},
        )
        if resp.status_code != 200:
            return False
        for line in resp.text.splitlines():
            if line.split(":", 1)[0].strip().upper() == suffix:
                return True
        return False
    except Exception:
        log.warning("HIBP check failed; allowing the password", exc_info=True)
        return False


def _banned_substrings():
    """Words banned anywhere in the password."""
    extra = toolkit.config.get("ckanext.sse.password.extra_blocklist", "")
    return _word_list(extra, BANNED_SUBSTRINGS)


def _banned_whole():
    """Words banned as the whole password, give or take a couple of letters.

    The file lives here rather than in the substring list because a
    compromised-password corpus is full of ordinary words, and banning those
    as substrings would ban the passphrases the standard asks for.
    """
    return _word_list("", BANNED_WHOLE) | _blocklist_file_words()


# --------------------------------------------------------------------------
# Strength
# --------------------------------------------------------------------------


def policy_rules(privileged=None):
    """The policy in words, for error messages and for the forms.

    Generated from the live configuration rather than written out twice: a
    hint that disagrees with the validator is worse than no hint.

    ``privileged`` defaults to whoever is signed in, so a sysadmin editing
    their own profile is shown the 15-character rule that will actually be
    applied to them.
    """
    if privileged is None:
        privileged = is_privileged(_current_user())

    rules = [
        _("be between {min} and {max} characters long").format(
            min=min_length(privileged), max=max_length()
        ),
        # The standard prefers passphrases, so the hint suggests one rather
        # than leaving people to invent something that merely passes.
        _("preferably be a passphrase of three or more random words"),
    ]
    if require_character_classes():
        rules.append(
            _("contain an uppercase letter, a lowercase letter, a digit and a "
              "symbol")
        )
    rules += [
        _("not repeat the same character more than {n} times in a row").format(
            n=max_repeat()
        ),
        _("not contain ascending or descending sequences, such as 123 or "
          "abcd"),
        _("not be a common password, a single dictionary word, or contain "
          "your username, full name or email address"),
    ]
    if history_length():
        rules.append(
            _("not be one of your {n} previous passwords, nor one of them "
              "with the number changed").format(n=history_length())
        )
    if expiry_days(privileged):
        rules.append(
            _("be changed at least every {n} days").format(
                n=expiry_days(privileged)
            )
        )
    return rules


def _current_user():
    """The signed-in user, or ``None`` outside a request."""
    if not has_request_context():
        return None
    user = toolkit.current_user
    if user is None or getattr(user, "is_anonymous", True):
        return None
    return user


def _normalise(password, undo_substitutions):
    """The password reduced to letters, optionally with leetspeak undone."""
    text = password.lower()
    if undo_substitutions:
        text = text.translate(LEET_MAP)
    return "".join(char for char in text if char.isalpha())


def _has_repeat(password):
    """Whether one character repeats more times in a row than allowed."""
    return re.search(r"(.)\1{%d,}" % max_repeat(), password) is not None


def _has_sequence(password):
    """Whether the password contains a run of consecutive codepoints.

    Catches ``123`` and ``abcd`` in either direction. Codepoint arithmetic
    rather than a keyboard map: ``qwerty`` and friends are handled by the word
    list, and the point here is the ascending and descending runs the standard
    names.

    Digits and letters are counted separately because the standard is explicit
    about number sequences and silent about letters, so digits are held to the
    shorter run.
    """
    digits = max_digit_sequence()
    letters = max_letter_sequence()

    start = 0
    step = 0
    for index in range(1, len(password)):
        delta = ord(password[index]) - ord(password[index - 1])
        if delta in (1, -1) and step in (0, delta):
            step = delta
            continue
        if _sequence_too_long(password[start:index], digits, letters):
            return True
        # A pair that broke the run because it runs the other way still starts
        # a run of its own.
        if delta in (1, -1):
            start, step = index - 1, delta
        else:
            start, step = index, 0
    return _sequence_too_long(password[start:], digits, letters)


def _sequence_too_long(run, digits, letters):
    """Whether one run of consecutive codepoints is over its limit.

    A mixed run ("yz01") is neither digits nor letters and is left alone --
    nobody types that as a sequence, and the standard is about the ones people
    do type.
    """
    if len(run) > digits and run.isdigit():
        return True
    return len(run) > letters and run.isalpha()


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


def check_strength(password, identifiers=(), privileged=False):
    """Every way ``password`` fails the policy, as a list of phrases.

    Phrases, not sentences: the caller joins them into one message because
    CKAN's ``error_summary`` only ever renders the first error per field, so
    reporting the failures separately would hide all but one of them.
    """
    if not isinstance(password, str):
        return [_("be a string")]

    minimum = min_length(privileged)
    failures = []
    if len(password) < minimum:
        failures.append(
            _("be at least {n} characters long").format(n=minimum)
        )
    if len(password) > max_length():
        failures.append(
            _("be no more than {n} characters long").format(n=max_length())
        )

    if require_character_classes():
        missing = []
        if not any(char.islower() for char in password):
            missing.append(_("a lowercase letter"))
        if not any(char.isupper() for char in password):
            missing.append(_("an uppercase letter"))
        if not any(char.isdigit() for char in password):
            missing.append(_("a digit"))
        # Anything that is not a letter or a digit counts, including a space,
        # so passphrases are not pushed towards punctuation soup.
        if not any(not char.isalnum() for char in password):
            missing.append(_("a symbol"))
        if missing:
            failures.append(_("contain {}").format(", ".join(missing)))

    if _has_repeat(password):
        failures.append(
            _("not repeat the same character more than {n} times in a "
              "row").format(n=max_repeat())
        )
    if _has_sequence(password):
        failures.append(
            _("not contain ascending or descending sequences such as 123 or "
              "abcd")
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
    touched. Checked against the privileged minimum whoever it is for, which
    also puts it at the 20 characters the standard asks of service accounts.
    """
    floor = max(min_length(privileged=True), DEFAULT_SERVICE_ACCOUNT_LENGTH)
    length = min(max(length or floor, floor), max_length())
    alphabet = string.ascii_letters + string.digits + GENERATED_SYMBOLS
    while True:
        candidate = "".join(
            secrets.choice(alphabet) for _unused in range(length)
        )
        if not check_strength(candidate, privileged=True):
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

    return any(_matches(password, stored) for stored in hashes)


def _matches(password, stored):
    """Whether ``password`` is the one behind ``stored``, tolerating junk."""
    if not stored:
        return False
    try:
        # Legacy sha1 hashes (CKAN < 2.0) are not pbkdf2 and make verify
        # raise. They belong to passwords nobody can still be reusing
        # deliberately, so skipping them is no loss.
        if not pbkdf2_sha512.identify(stored):
            return False
        return bool(pbkdf2_sha512.verify(password, stored))
    except (ValueError, TypeError):
        return False


def _increment_window():
    return _int_config("ckanext.sse.password.increment_window",
                       DEFAULT_INCREMENT_WINDOW)


def incremental_variants(password):
    """Passwords that ``password`` could be a numeric bump of.

    IA-5.1 forbids a password being "changed incrementally on password
    change, e.g. Welcome100, Welcome101, Welcome102". Only the hashes of
    previous passwords are stored, so the previous one cannot be read and
    compared -- instead the candidates it *would* have been are reconstructed
    from the new password and each is verified against the stored hash.

    The last run of digits anywhere in the password is the one varied, so
    "Summer2024!" catches "Summer2023!" as well as the trailing-number case
    the standard spells out. Both zero-padded and bare forms are produced,
    since "Welcome09" -> "Welcome10" changes the width. Dropping the digits
    entirely covers "Welcome" -> "Welcome1".
    """
    runs = list(re.finditer(r"\d+", password))
    if not runs:
        return []

    run = runs[-1]
    prefix, digits, suffix = (
        password[:run.start()], run.group(), password[run.end():]
    )
    value = int(digits)
    width = len(digits)

    variants = {prefix + suffix}
    for delta in range(1, _increment_window() + 1):
        for candidate in (value - delta, value + delta):
            if candidate < 0:
                continue
            variants.add(prefix + str(candidate) + suffix)
            variants.add(prefix + str(candidate).zfill(width) + suffix)

    variants.discard(password)
    return sorted(variants)


def is_incremental(password, user):
    """Whether ``password`` is the user's current password with a bumped number.

    Checked against the current password alone, not the whole history: the
    standard's wording is about a password being changed incrementally *on
    password change*, and each extra hash multiplies the number of pbkdf2
    verifications by the size of the candidate set.
    """
    stored = getattr(user, "password", None) if user is not None else None
    if not stored:
        return False
    return any(_matches(variant, stored)
               for variant in incremental_variants(password))


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

    # A sysadmin is held to the administration-account minimum, whether the
    # flag is already on the row or is being granted in this very call.
    granting = data.get(("sysadmin",))
    if granting is None or isinstance(granting, Missing):
        granting = False
    privileged = is_privileged(user) or toolkit.asbool(granting)

    failures = check_strength(value, identifiers, privileged=privileged)
    if failures:
        errors[("password",)].append(
            _("Your password must {}.").format("; ".join(failures))
        )
        # Stop here rather than also running the reuse checks: a password that
        # fails the policy is being rejected either way, and those cost a
        # pbkdf2 verification apiece.
        return

    if is_reused(value, user):
        errors[("password",)].append(
            _("You have used this password before. Please choose a password "
              "you have not used on this account.")
        )
        return

    if is_incremental(value, user):
        errors[("password",)].append(
            _("This is your current password with the number changed. Please "
              "choose a different password rather than an increment of the "
              "one it replaces.")
        )
        return

    # Last, because it is a network call: only reached by a password that has
    # passed every local check. Not run from ``check_strength`` (and so not
    # from ``generate_password``), which would hit the API per candidate.
    if hibp_check() and _is_pwned(value):
        errors[("password",)].append(
            _("This password has appeared in a known data breach. Please "
              "choose a different password.")
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
    days = expiry_days(is_privileged(user))
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


# Any date far enough in the past to be expired under any configured window.
_FORCE_EXPIRE_DATE = datetime.datetime(2000, 1, 1)


def force_expire(name):
    """Force a user to change their password at next login (IA-5.1).

    For "changed immediately should compromise be suspected". Reuses the
    rotation machinery rather than inventing a flag: the newest password-history
    row is back-dated, so ``is_expired`` becomes true and the existing
    ``before_app_request`` redirect sends the user to the change-password form.
    Setting a new password writes a fresh row and clears the condition.

    Returns the user, or ``None`` -- including for an account with no local
    password (an SSO-only user has nothing to rotate).
    """
    user = core_model.User.get(name)
    if user is None:
        return None

    row = sync_history(user)
    if row is None:
        return None

    row.created_at = _FORCE_EXPIRE_DATE
    Session.commit()

    if has_request_context():
        setattr(g, _LATEST_ATTR, row)
    return user


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

    user = toolkit.current_user
    if user is None or getattr(user, "is_anonymous", True):
        return None
    if not expiry_days(is_privileged(user)) and not warn_days():
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
          "before continuing.").format(
              days=expiry_days(is_privileged(user)))
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
