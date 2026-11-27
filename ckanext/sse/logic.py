# coding: utf8

from __future__ import unicode_literals
import ckan.authz as authz
from ckan.common import _
from ckan.model.user import AnonymousUser
from ckan.views.admin import _get_sysadmins as sysadmins
from ckan.lib.base import render
import ckan.lib.mailer as mailer
import ckan.logic as logic
import ckan.plugins.toolkit as toolkit
import json
from ckan.lib.base import render as render_jinja2
import os

try:
    # CKAN 2.7 and later
    from ckan.common import config
except ImportError:
    # CKAN 2.6 and earlier
    from pylons import config

from logging import getLogger

log = getLogger(__name__)


def restricted_get_username_from_context(context):
    auth_user_obj = context.get("auth_user_obj", None)
    user_name = ""
    if isinstance(auth_user_obj, AnonymousUser):
        return None
    if auth_user_obj:
        user_name = auth_user_obj.as_dict().get("name", "")
    else:
        if authz.get_user_id_for_username(context.get("user"), allow_none=True):
            user_name = context.get("user", "")
    if user_name == '':
        return None
    return user_name


def restricted_get_restricted_dict(resource_dict):
    restricted_dict = {"level": "public", "allowed_users": []}

    if resource_dict:
        restricted_level = resource_dict.get("level", "public")
        allowed_users = resource_dict.get("allowed_users", [])
        if not isinstance(allowed_users, list):
            allowed_users = allowed_users.split(",")
        restricted_dict = {
            "level": restricted_level,
            "allowed_users": allowed_users,
        }

    return restricted_dict


def restricted_check_user_resource_access(user, resource_dict, package_dict):
    restricted_dict = restricted_get_restricted_dict(resource_dict)

    restricted_level = restricted_dict.get("level", 'public')
    allowed_users = restricted_dict.get("allowed_users", [])

    # Public resources (DEFAULT)
    if not restricted_level or restricted_level == "public":
        return {"success": True}

    # Registered user
    if not user:
        return {
            "success": False,
            "msg": "Resource access restricted to registered users",
        }
    else:
        if restricted_level == "registered":
            return {"success": True}

    # Since we have a user, check if it is in the allowed list
    if user in allowed_users:
        return {"success": True}
    elif restricted_level == "only_allowed_users":
        return {
            "success": False,
            "msg": "Resource access restricted to allowed users only",
        }

    # Get organization list
    user_organization_dict = {}

    context = {"user": user}
    data_dict = {"permission": "read"}

    for org in logic.get_action("organization_list_for_user")(context, data_dict):
        name = org.get("name", "")
        id = org.get("id", "")
        if name and id:
            user_organization_dict[id] = name

    # Any Organization Members (Trusted Users)
    if not user_organization_dict:
        return {
            "success": False,
            "msg": "Resource access restricted to members of an organization",
        }

    if restricted_level == "any_organization":
        return {"success": True}

    pkg_organization_id = package_dict.get("owner_org", "")

    # Same Organization Members
    if restricted_level == "same_organization":
        if pkg_organization_id in user_organization_dict.keys():
            return {"success": True}

    return {
        "success": False,
        "msg": (
            "Resource access restricted to same " "organization ({}) members"
        ).format(pkg_organization_id),
    }


def _portal_url():
    # Emails link to the public portal frontend, not CKAN: recipients sign in
    # there to see the details that no longer travel inside the email (SC-8 / AC-21).
    return os.environ.get('CKAN_FRONTEND_SITE_URL') or config.get('ckan.site_url')


def _generic_mail_vars(site_title=None, site_url=None):
    return {
        'site_title': site_title or os.environ.get('CKAN_FRONTEND_SITE_TITLE') or config.get('ckan.site_title'),
        'site_url': site_url or _portal_url(),
        'portal_url': _portal_url(),
        # Where requesters read the status and the admin's reason.
        'access_requests_url': _portal_url().rstrip('/') + '/my-followed-data/access-requests',
    }


def mail_allowed_user(user_id, package, org_id, package_url=None, site_title=None, site_url=None):
    log.debug('restricted_mail_allowed_user: Notifying "{}"'.format(user_id))
    try:
        context = {}
        context["ignore_auth"] = True
        context["keep_email"] = True
        user = toolkit.get_action("user_show")(context, {"id": user_id})
        user_email = user["email"]
        user_name = user.get("display_name", user["name"])

        mail_body = restricted_allowed_user_mail_body(
            user, package, package_url, site_title, site_url)
        # Fixed subject: dataset name must not appear in email metadata.
        mail_subject = _("Your access request has been approved")

        mailer.mail_recipient(user_name, user_email, mail_subject, mail_body)

        mailer.mail_recipient(
            'Organization Administrators',
            os.environ.get('CKANEXT__SSE__ADMINS_EMAIL'),
            "Fwd: {}".format(mail_subject),
            mail_body,
        )

    except Exception as e:
        log.warning(
            (
                "restricted_mail_allowed_user: " 'Failed to send mail to "{0}": {1}'
            ).format(user_id, e)
        )


def restricted_allowed_user_mail_body(user, package, package_link=None, site_title=None, site_url=None):
    # package/package_link stay in the signature for existing callers, but the
    # body deliberately no longer names the dataset.
    extra_vars = _generic_mail_vars(site_title, site_url)
    extra_vars["user_name"] = user.get("display_name", user["name"])

    return render_jinja2("restricted/emails/restricted_user_allowed.txt", extra_vars)


def restricted_notify_allowed_users(previous_value, updated_resource):

    def _safe_json_loads(json_string, default={}):
        try:
            return json.loads(json_string)
        except Exception:
            return default

    previous_restricted = _safe_json_loads(previous_value)
    updated_restricted = _safe_json_loads(
        updated_resource.get("restricted", ""))

    # compare restricted users_allowed values
    updated_allowed_users = set(
        updated_restricted.get("allowed_users", "").split(","))
    if updated_allowed_users:
        previous_allowed_users = previous_restricted.get(
            "allowed_users", "").split(",")
        for user_id in updated_allowed_users:
            if user_id not in previous_allowed_users:
                mail_allowed_user(user_id, updated_resource)


def get_org_admins(context, org_id_or_name):
    """
    Retrieves a list of admin users for a given organization.

    Args:
        context: The context
        org_id_or_name: The ID or name of the organization.

    Returns:
        A list of dictionaries, where each dictionary represents an admin user
        and contains their details (e.g., 'id', 'name', 'email'). Returns an
        empty list if the organization is not found or has no admins. Raises
        an exception if there's an error retrieving user details.
    """

    try:
        org_data = toolkit.get_action('organization_show')(
            context, {'id': org_id_or_name, 'include_users': True})
        org_users = org_data.get('users', [])

        admin_users = []
        for user_role in org_users:
            if user_role['capacity'] == 'admin' or user_role.get('sysadmin'):
                user_id = user_role['id']

                try:
                    user_data = logic.get_action('user_show')(
                        {"user": os.environ.get('CKAN_SYSADMIN_NAME')}, {'id': user_id})
                    admin_users.append(user_data)
                except toolkit.ObjectNotFound:
                    print(f"Warning: User with ID {user_id} not found.")
                    continue
                except Exception as e:
                    raise Exception(f"Error getting user details: {e}")

        return admin_users

    except toolkit.ObjectNotFound:
        return []
    except Exception as e:
        raise Exception(f"Error getting organization details: {e}")


def send_request_mail_to_org_admins(data):
    success = False
    try:
        access_request_dashboard_link = toolkit.url_for(
            action='access_requests_dashboard',
            controller='access_requests')

        extra_vars = _generic_mail_vars(data.get('site_title'), data.get('site_url'))
        # Admins review inside CKAN, so their link stays on the CKAN site.
        extra_vars['access_request_dashboard_link'] = \
            f"{config.get('ckan.site_url')}{access_request_dashboard_link}"

        subject = _('A new dataset access request requires review')

        # No reply-to: it would put the requester's address in the headers.
        mailer.mail_recipient(
            recipient_name='Organization Administrators',
            recipient_email=os.environ.get('CKANEXT__SSE__ADMINS_EMAIL'),
            subject=subject,
            body=render('restricted/emails/restricted_access_request.txt', extra_vars),
            body_html=None)

        user_vars = _generic_mail_vars()
        user_vars['user_name'] = data.get('user_name') or 'User'
        mailer.mail_recipient(
            recipient_name=data.get('user_name', 'User'),
            recipient_email=data.get('user_email'),
            subject=_('Your access request has been received'),
            body=render('restricted/emails/restricted_access_request_received.txt', user_vars),
            body_html=None)
        success = True

    except mailer.MailerException as mailer_exception:
        log.error('Can not access request mail after registration.')
        log.error(mailer_exception)

    return success


def mail_rejected_user(data, rejection_message: str, status):
    # rejection_message is accepted for existing callers but never emailed: it
    # is admin free text, and the client asked for details to stay in the portal.
    success = False
    try:
        extra_vars = _generic_mail_vars(data.get('site_title'), data.get('site_url'))
        extra_vars['user_name'] = data.get('user_name', '')

        body = render(
            'restricted/emails/restricted_access_request_rejected.txt', extra_vars)
        subject = _('The status of your access request has changed')

        mailer.mail_recipient(
            recipient_name=data.get('user_name', ''),
            recipient_email=data.get('user_email'),
            subject=subject, body=body, body_html=None)

        mailer.mail_recipient(
            recipient_name='Organization Administrators',
            recipient_email=os.environ.get('CKANEXT__SSE__ADMINS_EMAIL'),
            subject='Fwd: ' + subject, body=body, body_html=None)

        success = True

    except mailer.MailerException as mailer_exception:
        log.error('Can not access request mail after registration.')
        log.error(mailer_exception)

    return success


def is_user_id_present_in_the_dict_list(user_id, list):
    if not list or len(list) == 0:
        return False
    return any(user_id == value for dict in list for value in dict.values())


def reuse_email_notification(reuse_data, _type, feedback=None):
    """
    Send email notification when a data reuse submission status changes.

    Args:
        submission: The FormResponse object that was updated
        _type: The new status ('approved' or 'rejected or 'new')
    """
    try:

        notification_email = []

        if _type == "new":
            notification_email.append(
                {'email': 'Ethan.Sian@sse.com', 'name': "Ethan Sian"})
            notification_email.append(
                {'email': 'Jeff.Alexander@sse.com', 'name': "Jeff Alexander"})
            notification_email.append(
                {'email': 'data@sse.com', 'name': "SSEN Data"})
        else:
            notification_email.append({
                'email': reuse_data["data"].get("email_address"),
                'name': reuse_data["data"].get("full_name", "Submitter"),
            })
        
        if not notification_email:
            log.warning(f"No email address found for submission {reuse_data['id']}")
            return False

        for email in notification_email:
            extra_vars = { 
                "admin_name": email['name'],
                "site_title": os.environ.get("CKAN_FRONTEND_SITE_TITLE")
                or config.get("ckan.site_title"),
                "site_url": os.environ.get("CKAN_FRONTEND_SITE_URL")
                or config.get("ckan.site_url"),
                "ckan_site_url": config.get("ckan.site_url"),
                "data": reuse_data,
            }
            if _type == "approved":
                template = "data_reuse/emails/submission_approved.txt"
                subject = _("Your data reuse submission has been approved")
            elif _type == "rejected":
                template = "data_reuse/emails/submission_rejected.txt"
                subject = _("Update on your data reuse submission")
            elif _type == "new":
                template = "data_reuse/emails/submission_new.txt"
                subject = _("New data reuse submission has been received")
            
            body = render(template, extra_vars)
            try:
                mailer.mail_recipient(email['name'], email['email'], subject, body)
            except Exception as e:
                log.warning(f"Failed to send {_type} email for submission {reuse_data['id']}: {e}")
                pass
        return True

    except Exception as e:
        log.warning(f"Failed to send {_type} email for submission {reuse_data['id']}: {e}")
        return False
