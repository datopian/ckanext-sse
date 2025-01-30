import json
import datetime
from sqlalchemy import or_
from ckan.plugins import toolkit as tk
from ckan.lib.helpers import helper_functions as helpers
from ckanext.scheming.helpers import scheming_field_choices, scheming_get_dataset_schema, scheming_field_by_name
import ckan.model as model
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

def _fix_package_show_groups(data_dict):
    datasets = []
    if type(data_dict) != list:
        datasets = [data_dict]
    
    group_ids = list(set([g.get("id") for dataset in datasets for g in dataset.get("groups")]))
    groups_q = model.Session.query(model.Group).filter(model.Group.id.in_(group_ids))
    groups = groups_q.all()
    groups_lu_table = {g.id: g for g in groups}
    
    for dataset in datasets:
        dataset_groups = dataset.get("groups", [])
        dataset_segregated_groups = {"groups": []}
        for group in dataset_groups:
            id = group.get("id")
            db_group = groups_lu_table.get(id)
            group_type = db_group.type + "s"
            if not group_type in dataset_segregated_groups:
                dataset_segregated_groups[group_type] = []
            dataset_segregated_groups[group_type].append(group)
        dataset.update(dataset_segregated_groups)


@tk.side_effect_free
@tk.chained_action
def package_show(up_func, context, data_dict):
    result = up_func(context, data_dict)

    frequencies = _get_dataset_schema_frequency_options()
    _transform_package_show(result, frequencies)
    _fix_package_show_groups(result)

    
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
