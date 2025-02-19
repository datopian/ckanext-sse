from __future__ import unicode_literals
import json
import datetime
from sqlalchemy import or_
from ckan.common import _
from ckan.plugins import toolkit as tk
from ckanext.scheming.helpers import scheming_field_choices, scheming_get_dataset_schema, scheming_field_by_name
from sqlalchemy import func
import string
import random
from .model import PackageAccessRequest
from .schemas import package_request_access_schema
import os


from logging import getLogger
import ckan
import ckan.logic
import ckan.lib.navl.dictization_functions as dictization_functions
from ckan.plugins import toolkit as tk
import ckan.logic as logic
import ckan.plugins.toolkit as toolkit
from .logic import send_request_mail_to_org_admins
from .schemas import package_request_access_schema

DataError = dictization_functions.DataError
unflatten = dictization_functions.unflatten


log = getLogger(__name__)


NotFound = ckan.logic.NotFound
NotAuthorized = ckan.logic.NotAuthorized

generic_error_message = {
    'errors': {'auth': [_('Unable to authenticate user')]},
    'error_summary': {_('auth'): _('Unable to authenticate user')},
}


def _convert_dct_to_stringify_json(data_dict):
    for resource in data_dict.get("resources", []):
        if resource.get("schema"):
            if isinstance(resource.get("schema"), list) or isinstance(
                resource.get("schema"), dict
            ):
                resource["schema"] = json.dumps(resource["schema"])

    coverage = data_dict.get("coverage", False)
    if coverage:
        if isinstance(coverage, list) or isinstance(coverage, dict):
            data_dict["coverage"] = json.dumps(coverage)
    return data_dict


@tk.chained_action
def package_create(up_func, context, data_dict):
    data_dict = _convert_dct_to_stringify_json(data_dict)
    result = up_func(context, data_dict)
    return result


@logic.validate(package_request_access_schema)
@tk.side_effect_free
def request_access_to_dataset(context, data_dict):
    if toolkit.current_user.is_anonymous:
        raise NotAuthorized
    user = toolkit.get_action('user_show')(
        {'user': os.environ.get('CKAN_SYSADMIN_NAME')}, {'id': toolkit.current_user.id})

    already_have_access_error = {
        'success': False,
        'errors': {'validation': [_('You already have access to the dataset\'s resources')]},
    }

    if user.get('sysadmin'):
        return already_have_access_error

    pkg = None

    try:
        pkg = toolkit.get_action('package_show')(
            context, {'id': data_dict.get('package_id')})
        data_dict['pkg_dict'] = pkg
    except toolkit.ObjectNotFound:
        raise NotFound('Dataset not found')
    except Exception as e:
        log.error(e)
        return {
            'success': False,
            'errors': {'error': [_('Exception retrieving dataset to send mail')]},
            'error_summary': {_('error'): _('Exception retrieving dataset to send mail')},
        }

    if pkg.get('private'):
        return {
            'success': False,
            'errors': {'validation': [_('Dataset not found or private')]},
        }

    is_user_collaborator_already = any(user.get('id') == value for dict in tk.get_action('package_collaborator_list')(
        {'ignore_auth': True}, {'id': pkg.get('id')}) for value in dict.values())

    if is_user_collaborator_already:
        return already_have_access_error

    is_there_request_access_already_created_for_the_user = PackageAccessRequest.get_by_package_user_and_status(
        pkg.get('id'), user.get('id'), 'pending')

    if len(is_there_request_access_already_created_for_the_user) > 0:
        return {
            'success': False,
            'errors': {'validation': [_('Request already created for this resource')]},
        }

    PackageAccessRequest.create(package_id=pkg.get('id'), user_id=user.get('id'), org_id=pkg.get(
        'organization').get('id'), message=data_dict.get('message'))

    site_title = os.environ.get('CKAN_FRONTEND_SITE_TITLE')

    email_notification_dict = {
        'user_id': user.get('id'),
        'site_title': site_title,
        'user_name': user.get('full_name') or user.get('display_name') or user.get('name'),
        'user_email': user.get('email'),
        'package_name': pkg.get('name') or pkg.get('id'),
        'package_title': pkg.get('title') or pkg.get('name') or pkg.get('id'),
        'package_id': pkg.get('id'),
        'user_organization': data_dict.get('user_organization', ''),
        'org_id': pkg.get('organization').get('id'),
        'package_type': pkg.get('type'),
        'message': data_dict.get('message'),
    }

    success = send_request_mail_to_org_admins(email_notification_dict)

    return {"success": success, 'message': 'Your request was sent successfully' if success else 'Your request was not registered'}


@tk.chained_action
def package_update(up_func, context, data_dict):
    data_dict = _convert_dct_to_stringify_json(data_dict)
    result = up_func(context, data_dict)
    return result


def _get_dataset_schema_frequency_options():
    schema = scheming_get_dataset_schema("dataset")
    schema_dataset_fields = schema.get("dataset_fields")
    frequency_field = scheming_field_by_name(
        schema_dataset_fields, "frequency")
    frequencies = scheming_field_choices(frequency_field)
    return frequencies


def _transform_package_show(package_dict, frequencies, context):
    resources = package_dict.get("resources", [])
    regular_resources = list(filter(lambda x: x.get(
        "resource_type") == "regular", resources))
    frequency = package_dict.get("frequency", None)

    max_last_modified = None
    for resource in regular_resources:
        last_modified = resource.get("last_modified")
        datastore_modified = resource.get("last_datastore_modified")
        metadata_modified = resource.get("metadata_modified")

        dates = [max_last_modified, datastore_modified, last_modified]
        # Only use metadata_modified if both dates are unset
        if not any(dates):
            dates.append(metadata_modified)

        dates = list(filter(lambda x: x is not None, dates))
        max_last_modified = max(dates)

    package_dict['last_data_update'] = max_last_modified

    expiration = None
    for f in frequencies:
        value = f.get("value")
        if value == frequency:
            expiration = f.get("expiration")

    is_up_to_date = None
    if expiration is not None and max_last_modified is not None:
        now = datetime.datetime.utcnow()
        last_data_update_date = datetime.datetime.fromisoformat(
            max_last_modified)
        update_required_after = last_data_update_date + \
            datetime.timedelta(**expiration)
        is_up_to_date = now < update_required_after

    package_dict["is_up_to_date"] = is_up_to_date

    user = context.get('auth_user_obj')
    package_dict['has_access_to_resources'] = True

    if package_dict.get('is_restricted'):
        if not user or user.is_anonymous or (not user.sysadmin and not any(user.id == value for dict in tk.get_action('package_collaborator_list')(
                {'ignore_auth': True}, {'id': package_dict.get('id')}) for value in dict.values())):
            package_dict['has_access_to_resources'] = False

    if not package_dict['has_access_to_resources']:
        package_dict['resources'] = hide_resources_field(
            package_dict['resources'])


def user_login(context, data_dict):
    try:
        frontend_secret = os.getenv("CKANEXT__SSE__CLIENT_AUTH_SECRET")
        client_secret = data_dict['client_secret']

        if frontend_secret != client_secret:
            return {
                'errors': {'auth': [_('Unable to authenticate user')]},
                'error_summary': {_('auth'): _('Client not authorized to authenticate')},
            }

        session = context['session']
        email = data_dict['email']
        model = context['model']
        context['ignore_auth'] = True

        if not email:
            return generic_error_message

        user = session.query(model.User).filter(func.lower(
            model.User.email) == func.lower(email)).first()

        if not user:
            password_length = 10
            password = ''.join(
                random.choice(string.ascii_letters + string.digits)
                for _ in range(password_length)
            )

            user_name = ''.join(
                c.lower() if c.isalnum() else '_' for c in email.split('@')[0]
            )

            user = tk.get_action('user_create')(
                context,
                {
                    'name': user_name,
                    'display_name': data_dict['name'],
                    'fullname': data_dict['name'],
                    'email': email,
                    'password': password,
                    'state': 'active',
                },
            )
        else:
            user = user.as_dict()

        return _generate_token(context, user)
    except Exception as e:
        log.error(e)
        return json.dumps({"error": True})


def _generate_token(context, user):
    context['ignore_auth'] = True
    user['frontend_token'] = None

    try:
        api_tokens = tk.get_action('api_token_list')(
            context, {'user_id': user['name']}
        )

        for token in api_tokens:
            if token['name'] == 'frontend_token':
                tk.get_action('api_token_revoke')(
                    context, {'jti': token['id']})

        frontend_token = tk.get_action('api_token_create')(
            context, {'user': user['name'], 'name': 'frontend_token'}
        )

        user['frontend_token'] = frontend_token.get('token')

    except Exception as e:
        log.error(e)

    return user


@tk.side_effect_free
@tk.chained_action
def package_show(up_func, context, data_dict):
    result = up_func(context, data_dict)
    formats = set()
    for resource in result["resources"]:
        if resource.get("format") and resource.get('resource_type') != 'documentation':
            formats.add(resource.get("format"))
    result["format"] = list(formats)

    frequencies = _get_dataset_schema_frequency_options()
    _transform_package_show(result, frequencies, context)

    return result


def hide_resources_field(resources=[]):
    if not resources or len(resources) == 0:
        return []

    for resource in resources:
        if resource.get('resource_type') != 'documentation':
            resource['url'] = None

    return resources


@tk.side_effect_free
def search_package_list(context, data_dict):
    """Return a list of datasets that match the given query.
    :param q: the query string
    :type q: string
    :param limit: the maximum number of results to return
    :type limit: int
    :rtype: list of dictionaries
    """
    model = context["model"]
    session = context["session"]
    q = data_dict.get("q", "")
    limit = data_dict.get("limit", 10)

    if not q:
        return []

    query = (
        session.query(model.Package.name, model.Package.title)
        .filter(model.Package.state == "active")
        .filter(model.Package.private == False)
        .filter(
            or_(
                model.Package.name.ilike("%{0}%".format(q)),
                model.Package.title.ilike("%{0}%".format(q)),
            )
        )
        .limit(limit)
    )

    return [name for name, title in query.all()]


@tk.side_effect_free
@tk.chained_action
def package_search(up_func, context, data_dict):
    result = up_func(context, data_dict)
    datasets = result.get("results", [])
    frequencies = _get_dataset_schema_frequency_options()
    for d in datasets:
        _transform_package_show(d, frequencies, context)
    return result
