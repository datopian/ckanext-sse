import json
import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import logging
from ckanext.sse import action
import ckanext.sse.activity as activity
from ckanext.sse.validators import (
    coverage_json_object,
    resource_type_validator,
    schema_json_object,
    schema_output_string_json,
    ib1_trust_framework_validator,
    ib1_sensitivity_class_validator,
    ib1_dataset_assurance_validator,
)

log = logging.getLogger(__name__)


class SsePlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IValidators)
    plugins.implements(plugins.IActions)
    plugins.implements(plugins.IPackageController, inherit=True)

    # IConfigurer
    def update_config(self, config_):
        toolkit.add_template_directory(config_, "templates")
        toolkit.add_public_directory(config_, "public")
        toolkit.add_resource("assets", "sse")

    # IPackageController
    def create(self, entity):
        if (entity.type == 'showcase'):
            return entity

        if entity.owner_org:
            org_name = toolkit.get_action("organization_show")(
                {"ignore_auth": True}, {"id": entity.owner_org}
            )["name"]
            entity.url = "{0}/@{1}/{2}".format(
                toolkit.config.get("ckanext.dcat.base_uri", "").rstrip("/"),
                org_name,
                entity.name,
            )
        else:
            entity.url = "{0}/dataset/{1}".format(
                toolkit.config.get("ckanext.dcat.base_uri", "").rstrip("/"),
                entity.name,
            )
        return entity

    def edit(self, entity):
        if (entity.type == 'showcase'):
            return entity

        if entity.owner_org:
            org_name = toolkit.get_action("organization_show")(
                {"ignore_auth": True}, {"id": entity.owner_org}
            )["name"]
            entity.url = "{0}/@{1}/{2}".format(
                toolkit.config.get("ckanext.dcat.base_uri", "").rstrip("/"),
                org_name,
                entity.name,
            )
        else:
            entity.url = "{0}/dataset/{1}".format(
                toolkit.config.get("ckanext.dcat.base_uri", "").rstrip("/"),
                entity.name,
            )
        return entity

    # IPackageController
    def before_dataset_index(self, data_dict):
        if data_dict.get("coverage", False):
            data_dict["coverage"] = json.dumps(data_dict["coverage"])
        if data_dict.get("format"):
            data_dict["format"] = json.dumps(data_dict["format"])
        return data_dict

    # IValidators
    def get_validators(self):
        return {
            "coverage_json_object": coverage_json_object,
            "schema_json_object": schema_json_object,
            "resource_type_validator": resource_type_validator,
            "schema_output_string_json": schema_output_string_json,
            "ib1_trust_framework_validator": ib1_trust_framework_validator,
            "ib1_sensitivity_class_validator": ib1_sensitivity_class_validator,
            "ib1_dataset_assurance_validator": ib1_dataset_assurance_validator,
        }

    # IActions
    def get_actions(self):
        return {
            "package_create": action.package_create,
            "package_update": action.package_update,
            "package_show": action.package_show,
            "daily_report_activity": activity.dashboard_activity_list_for_all_users,
            "search_package_list": action.search_package_list,
        }
