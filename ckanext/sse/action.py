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
    formats = set()
    for resource in result["resources"]:
        if resource.get("format"):
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
