"""Tests for ckanext.sse.mail_suppression."""

import pytest
from flask_login import login_user

import ckan.lib.mailer as mailer
import ckan.model as model
from ckan.tests import factories

from ckanext.sse import mail_suppression


@pytest.fixture
def sent(monkeypatch):
    """Record deliveries instead of talking to SMTP, then install the hook."""
    calls = []

    def fake_mail_recipient(recipient_name, recipient_email, sender_name,
                            sender_url, subject, body, body_html=None,
                            headers=None, attachments=None):
        calls.append(recipient_email)

    monkeypatch.setattr(mailer, "_mail_recipient", fake_mail_recipient)
    mail_suppression.install()
    return calls


def send():
    mailer.mail_recipient("Reviewer", "reviewer@example.com", "Subject", "Body")


def signed_in(app, user_name):
    ctx = app.flask_app.test_request_context(
        "/", environ_overrides={"beaker.session": {}})
    ctx.push()
    login_user(model.User.get(user_name))
    return ctx


@pytest.mark.usefixtures("with_plugins", "clean_db")
class TestMailSuppression:
    @pytest.mark.ckan_config(mail_suppression.CONFIG_KEY, "dast-scanner")
    def test_listed_user_sends_nothing(self, app, sent):
        factories.User(name="dast-scanner")
        ctx = signed_in(app, "dast-scanner")
        try:
            send()
        finally:
            ctx.pop()
        assert sent == []

    @pytest.mark.ckan_config(mail_suppression.CONFIG_KEY, "dast-scanner")
    def test_other_users_still_send(self, app, sent):
        factories.User(name="publisher")
        ctx = signed_in(app, "publisher")
        try:
            send()
        finally:
            ctx.pop()
        assert sent == ["reviewer@example.com"]

    @pytest.mark.ckan_config(mail_suppression.CONFIG_KEY, "")
    def test_empty_setting_changes_nothing(self, app, sent):
        factories.User(name="dast-scanner")
        ctx = signed_in(app, "dast-scanner")
        try:
            send()
        finally:
            ctx.pop()
        assert sent == ["reviewer@example.com"]

    @pytest.mark.ckan_config(mail_suppression.CONFIG_KEY, "dast-scanner")
    def test_outside_a_request_mail_is_sent(self, sent):
        """CLI and background jobs have no acting user."""
        send()
        assert sent == ["reviewer@example.com"]

    @pytest.mark.ckan_config(mail_suppression.CONFIG_KEY, "other, dast-scanner")
    def test_comma_and_space_separated_list(self, app, sent):
        factories.User(name="dast-scanner")
        ctx = signed_in(app, "dast-scanner")
        try:
            send()
        finally:
            ctx.pop()
        assert sent == []

    def test_install_is_idempotent(self, sent):
        wrapped = mailer._mail_recipient
        mail_suppression.install()
        assert mailer._mail_recipient is wrapped
