import json
from sqlalchemy import or_
from ckan.plugins import toolkit as tk
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
    resources_formats = data_dict.get(
        'resources_formats', generate_resource_formats_array(context, data_dict))
    data_dict = _convert_dct_to_stringify_json(data_dict)
    data_dict['resources_formats'] = resources_formats
    result = up_func(context, data_dict)
    return result


@tk.chained_action
def package_update(up_func, context, data_dict):
    resources_formats = data_dict.get(
        'resources_formats', generate_resource_formats_array(context, data_dict))
    data_dict = _convert_dct_to_stringify_json(data_dict)
    data_dict['resources_formats'] = resources_formats
    result = up_func(context, data_dict)
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


def generate_resource_formats_array(context, package):
    import ckan.plugins.toolkit as toolkit
    resources_formats_set = set()
    for resource in package.get('resources', toolkit.get_action('package_show')(context, package).get('resources', [])):
        if resource.get('format'):
            resources_formats_set.add(resource.get('format'))

    resources_formats_list = []

    for format in resources_formats_set:
        resources_formats_list.append(format)

    return resources_formats_list
