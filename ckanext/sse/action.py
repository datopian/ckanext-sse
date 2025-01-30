import json
from sqlalchemy import or_
from ckan.plugins import toolkit as tk
from ckan.lib.helpers import helper_functions as helpers
import logging

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


@tk.side_effect_free
@tk.chained_action
def package_show(up_func, context, data_dict):
    result = up_func(context, data_dict)
    default_group_type = helpers.default_group_type('group')
    group_types = [default_group_type] + tk.get_action('scheming_group_schema_list')(
        context, {u'id': context['user']})
    group_list_action = tk.get_action(u'group_list')
    groups = []
    for group_type in group_types:
        groups += group_list_action(
            context, {'type': group_type, 'all_fields': True})
    groups_ids_by_type = dict()
    for group in groups:
        groups_ids = groups_ids_by_type.get(group.get('type'), set())
        groups_ids.add(group.get('id'))
        groups_ids_by_type[group.get('type')] = groups_ids

    if data_dict.get('group_type'):
        result['groups'] = [group for group in result.get('groups') if group.get(
            'id') in groups_ids_by_type.get(data_dict.get('group_type'))]
    else:
        result['groups'] = [group for group in result.get('groups') if group.get(
            'id') in groups_ids_by_type.get(default_group_type)]

    formats = set()
    for resource in result["resources"]:
        if resource.get("format") and resource.get('resource_type') != 'documentation':
            formats.add(resource.get("format"))
    result["format"] = list(formats)
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
