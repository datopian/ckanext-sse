"""Drop outgoing mail triggered by designated accounts.

Some accounts exist only to exercise the site automatically, for example the
account an authenticated DAST scan runs as. Every form it submits would
otherwise send real notifications (a data reuse submission emails the review
team, an access request emails organisation admins, and so on), so a scan can
flood real inboxes.

Listing such accounts in ``ckanext.sse.mail_suppressed_users`` (space or comma
separated usernames; env ``CKANEXT__SSE__MAIL_SUPPRESSED_USERS``) makes CKAN
skip sending any mail during a request made by one of them. The action itself
still runs, so the scan covers the same code paths; only the delivery is
skipped, and a log line records what would have been sent.

The hook sits on ``ckan.lib.mailer._mail_recipient``, the function every mail
path goes through (core ``mail_recipient``/``mail_user`` and every call in this
extension), so mail added later is covered without changes here. Mail sent
outside a request (CLI commands, background jobs) has no acting user and is
never suppressed. With the setting empty, which is the default, nothing changes.
"""

import functools
import inspect
import logging

import ckan.lib.mailer as mailer
import ckan.plugins.toolkit as toolkit
from flask import has_request_context

log = logging.getLogger(__name__)

CONFIG_KEY = "ckanext.sse.mail_suppressed_users"


def suppressed_users():
    """Usernames from the setting; accepts spaces and/or commas."""
    value = toolkit.config.get(CONFIG_KEY)
    if not value:
        return set()
    if isinstance(value, (list, tuple, set)):
        value = " ".join(value)
    return set(value.replace(",", " ").split())


def acting_user_name():
    """Name of the signed-in user of the current request, or None."""
    if not has_request_context():
        return None
    user = toolkit.current_user
    if user is not None and getattr(user, "is_authenticated", False):
        return getattr(user, "name", None)
    return None


def install():
    """Wrap ckan.lib.mailer._mail_recipient once (idempotent)."""
    original = mailer._mail_recipient
    if getattr(original, "_sse_mail_suppression", False):
        return
    signature = inspect.signature(original)

    @functools.wraps(original)
    def _mail_recipient(*args, **kwargs):
        user = acting_user_name()
        if user and user in suppressed_users():
            bound = signature.bind_partial(*args, **kwargs).arguments
            log.info(
                "Mail suppressed for %s: to=%s subject=%r",
                user,
                bound.get("recipient_email"),
                bound.get("subject"),
            )
            return None
        return original(*args, **kwargs)

    _mail_recipient._sse_mail_suppression = True
    mailer._mail_recipient = _mail_recipient
