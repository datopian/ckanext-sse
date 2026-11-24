"""Emails must stay generic: details live behind the portal login (SC-8 / AC-21)."""

import pytest

import ckan.lib.mailer as mailer

from ckanext.sse import logic

SECRET_BITS = [
    "Jane Doe",
    "jane.doe@example.com",
    "Example Energy Ltd",
    "needs half-hourly feeder data",
    "smart-meter-lv-usage",
    "Smart Meter LV Usage",
    "Not available for commercial use",
]

REQUEST = {
    "user_id": "u1",
    "user_name": "Jane Doe",
    "user_email": "jane.doe@example.com",
    "user_organization": "Example Energy Ltd",
    "message": "needs half-hourly feeder data",
    "package_name": "smart-meter-lv-usage",
    "package_title": "Smart Meter LV Usage",
    "package_id": "p1",
    "org_id": "o1",
}

REUSE = {
    "id": "r1",
    "package_id": "p1",
    "data": {
        "full_name": "Jane Doe",
        "email_address": "jane.doe@example.com",
        "title": "Smart Meter LV Usage heatmap",
        "organisation_name": "Example Energy Ltd",
        "description": "needs half-hourly feeder data",
    },
    "type": "example",
    "submitted_at": "2026-11-04",
}


@pytest.fixture
def sent(monkeypatch):
    """Capture every outgoing message instead of talking to SMTP."""
    calls = []

    def fake(recipient_name, recipient_email, subject, body, body_html=None,
             headers=None, attachments=None):
        calls.append(
            {"to": recipient_email, "subject": subject, "body": body,
             "headers": headers or {}})

    monkeypatch.setattr(mailer, "mail_recipient", fake)
    monkeypatch.setenv("CKANEXT__SSE__ADMINS_EMAIL", "admins@example.org")
    return calls


def assert_generic(calls):
    assert calls, "no email was sent"
    for call in calls:
        text = call["subject"] + "\n" + call["body"] + "\n" + str(call["headers"])
        for bit in SECRET_BITS:
            assert bit not in text, f"{bit!r} leaked into an email"


@pytest.mark.usefixtures("with_plugins")
class TestEmailContent:
    def test_access_request_emails(self, app, sent):
        with app.flask_app.test_request_context("/"):
            assert logic.send_request_mail_to_org_admins(dict(REQUEST))
        assert_generic(sent)
        assert {c["to"] for c in sent} == {"admins@example.org", "jane.doe@example.com"}

    def test_rejection_reason_is_not_emailed(self, app, sent):
        with app.flask_app.test_request_context("/"):
            logic.mail_rejected_user(
                dict(REQUEST), "Not available for commercial use", "rejected")
        assert_generic(sent)

    def test_reuse_new_has_no_submitter_details(self, app, sent):
        with app.flask_app.test_request_context("/"):
            logic.reuse_email_notification(REUSE, "new")
        assert_generic(sent)

    def test_reuse_rejected_has_no_submission_copy(self, app, sent):
        with app.flask_app.test_request_context("/"):
            logic.reuse_email_notification(REUSE, "rejected", feedback="Not available for commercial use")
        assert_generic(sent)
