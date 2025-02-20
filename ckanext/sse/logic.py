# coding: utf8

from __future__ import unicode_literals
import ckan.authz as authz
from ckan.common import _
from ckan.model.user import AnonymousUser

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


def restricted_mail_allowed_user(user_id, package, org_id, package_url=None, site_title=None, site_url=None):
    log.debug('restricted_mail_allowed_user: Notifying "{}"'.format(user_id))
    try:
        # Get user information
        context = {}
        context["ignore_auth"] = True
        context["keep_email"] = True
        user = toolkit.get_action("user_show")(context, {"id": user_id})
        user_email = user["email"]
        user_name = user.get("display_name", user["name"])
        package_name = package.get("name", package["id"])

        # maybe check user[activity_streams_email_notifications]==True

        mail_body = restricted_allowed_user_mail_body(
            user, package, package_url, site_title, site_url)
        mail_subject = _("Access granted to dataset {}'s resources").format(package_name)

        # Send mail to user
        mailer.mail_recipient(user_name, user_email, mail_subject, mail_body)
        # org_admins = get_org_admins({'ignore_auth': True}, org_id)

        # for admin in org_admins:
        # Send copy to admin
        # mailer.mail_recipient(
        #     admin.get('fullname') or admin.get(
        #         'display_name') or admin.get('name'),
        #     admin.get('email'),
        #     "Fwd: {}".format(mail_subject),
        #     mail_body,
        # )
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
    if not package_link:
        package_link = config.get("ckan.site_url") + toolkit.url_for(
            controller="package",
            action="read",
            id=package.get("package_id"),
            package_id=package.get("id"),
        )

    extra_vars = {
        "site_title": site_title or config.get("ckan.site_title"),
        "site_url": site_url or config.get("ckan.site_url"),
        "user_name": user.get("display_name", user["name"]),
        "package_name": package.get("name", package["id"]),
        "package_link": package_link,
        "package_url": package.get("url"),
    }

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
                restricted_mail_allowed_user(user_id, updated_resource)


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
    # org_admins = [admin for admin in get_org_admins(
    #     {'ignore_auth': True}, data.get('org_id')) if admin.get('email')]
    success = False
    try:
        access_request_dashboard_link = toolkit.url_for(
            action='access_requests_dashboard',
            controller='access_requests')

        package_link = toolkit.url_for(
            action='read',
            controller='dataset',
            id=data.get('package_name'),
            package_id=data.get('package_id'))

        extra_vars = {
            'site_title': data.get('site_title') or config.get('ckan.site_title'),
            'site_url': data.get('site_url') or config.get('ckan.site_url'),
            'maintainer_name': 'Organisation Administrator',
            'user_id': data.get('user_id', 'the user id'),
            'user_name': data.get('user_name', ''),
            'user_email': data.get('user_email', ''),
            'package_name': data.get('package_name', ''),
            'package_link': data.get('package_link') or f"{config.get('ckan.site_url')}{package_link}",
            'access_request_dashboard_link': f"{config.get('ckan.site_url')}{access_request_dashboard_link}",
            'user_organization': data.get('user_organization', 'No organisation informed'),
            'message': data.get('message', ''),
            'admin_email_to': config.get('email_to', 'email_to_undefined')}

        mail_template = 'restricted/emails/restricted_access_request.txt'
        body = render(mail_template, extra_vars)

        subject = \
            _('Access Request to {0}\'s ({1}) resources from {2}').format(
                data.get('package_title', ''),
                data.get('package_name', ''),
                data.get('user_name', ''))
        headers = {
            # 'CC': ",".join([admin_dict.get('email') for admin_dict in org_admins]),
            'reply-to': data.get('user_email')}

        # for admin_dict in org_admins:
        #     # CC doesn't work and mailer cannot send to multiple addresses
        #     mailer.mail_recipient(recipient_name=admin_dict.get('fullname') or admin_dict.get('display_name') or admin_dict.get('name'), recipient_email=admin_dict.get('email'), subject='Fwd: ' + subject, body=body,
        #                           body_html=None, headers=headers)

        mailer.mail_recipient(recipient_name='Organization Administrators', recipient_email=os.environ.get('CKANEXT__SSE__ADMINS_EMAIL'), subject='Fwd: ' + subject, body=body,
                              body_html=None, headers=headers)

        # Special copy for the user (no links)
        email = data.get('user_email')
        name = data.get('user_name', 'User')

        extra_vars['package_link'] = '[...]'
        extra_vars['access_request_dashboard_link'] = '[...]'
        extra_vars['admin_email_to'] = '[...]'
        extra_vars['site_url'] = os.environ.get(
            'CKAN_FRONTEND_SITE_URL') or config.get('ckan.site_url')
        extra_vars['site_title'] = os.environ.get(
            'CKAN_FRONTEND_SITE_TITLE') or config.get('ckan.site_title')

        body = render(
            'restricted/emails/restricted_access_request.txt', extra_vars)

        body_user = _(
            'Please find below a copy of the access '
            'request mail sent. \n\n >> {}'
        ).format(body.replace("\n", "\n >> "))
        mailer.mail_recipient(recipient_name=name, recipient_email=email, subject='Fwd: ' + subject, body=body_user,
                              body_html=None, headers=headers)
        success = True

    except mailer.MailerException as mailer_exception:
        log.error('Can not access request mail after registration.')
        log.error(mailer_exception)

    return success


def send_rejection_email_to(data, rejection_message: str, status):
    # org_admins = [admin for admin in get_org_admins(
    # {'ignore_auth': True}, data.get('org_id')) if admin.get('email')]
    try:
        extra_vars = {
            'site_title': data.get('site_title') or config.get('ckan.site_title'),
            'site_url': data.get('site_url') or config.get('ckan.site_url'),
            'user_name': data.get('user_name', ''),
            'user_email': data.get('user_email', ''),
            'status': status,
            'package_name': data.get('package_name', ''),
            'rejection_message': rejection_message,
            'admin_email_to': config.get('email_to', 'email_to_undefined')}

        mail_template = 'restricted/emails/restricted_access_request_rejected.txt'
        body = render(mail_template, extra_vars)

        subject = \
            _('Access Request to {0}\'s ({1}) resources from {2}').format(
                data.get('package_title', ''),
                data.get('package_name', ''),
                data.get('user_name', ''))

        mailer.mail_recipient(recipient_name=data.get('user_name', ''), recipient_email=data.get(
            'user_email'), subject='Fwd: ' + subject, body=body, body_html=None)

        body = render(mail_template, extra_vars)

        body_user = _(
            'Please find below a copy of the access '
            'request mail sent. \n\n >> {}'
        ).format(body.replace("\n", "\n >> "))

        headers = {
            # 'CC': ",".join([admin_dict.get('email') for admin_dict in org_admins]),
            'reply-to': data.get('user_email')}

        # for admin_dict in org_admins:
        #     mailer.mail_recipient(recipient_name=admin_dict.get('fullname') or admin_dict.get('display_name') or admin_dict.get('name'), recipient_email=admin_dict.get('email'), subject='Fwd: ' + subject, body=body_user,
        #                           body_html=None, headers=headers)
        mailer.mail_recipient(recipient_name='Organization Administrators', recipient_email=os.environ.get('CKANEXT__SSE__ADMINS_EMAIL'), subject='Fwd: ' + subject, body=body_user,
                              body_html=None, headers=headers)

        success = True

    except mailer.MailerException as mailer_exception:
        log.error('Can not access request mail after registration.')
        log.error(mailer_exception)

    return success


def is_user_id_present_in_the_dict_list(user_id, list):
        return any(user_id == value for dict in list for value in dict.values())