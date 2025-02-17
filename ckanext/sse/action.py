import json
import datetime
from sqlalchemy import or_
from ckan.common import _, config
from ckan.plugins import toolkit as tk
import ckan.lib.authenticator as authenticator
from ckanext.scheming.helpers import scheming_field_choices, scheming_get_dataset_schema, scheming_field_by_name
from sqlalchemy import func
import string
import random
import logging
import os

generic_error_message = {
    'errors': {'auth': [_('Unable to authenticate user')]},
    'error_summary': {_('auth'): _('Unable to authenticate user')},
}

log = logging.getLogger(__name__)


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


@tk.chained_action
def package_update(up_func, context, data_dict):
    data_dict = _convert_dct_to_stringify_json(data_dict)
    result = up_func(context, data_dict)
    return result


def _get_dataset_schema_frequency_options():
    schema = scheming_get_dataset_schema("dataset")
    schema_dataset_fields = schema.get("dataset_fields")
    frequency_field = scheming_field_by_name(schema_dataset_fields, "frequency")
    frequencies = scheming_field_choices(frequency_field)
    return frequencies


def _transform_package_show(package_dict, frequencies):
    resources = package_dict.get("resources", [])
    regular_resources = list(filter(lambda x: x.get("resource_type") == "regular", resources))
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
        last_data_update_date = datetime.datetime.fromisoformat(max_last_modified)
        update_required_after =  last_data_update_date + datetime.timedelta(**expiration)
        is_up_to_date = now < update_required_after

    package_dict["is_up_to_date"] = is_up_to_date



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
    _transform_package_show(result, frequencies)
    return result


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
        _transform_package_show(d, frequencies)
    return result
