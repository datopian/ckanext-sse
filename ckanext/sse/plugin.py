import json
import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import logging
from ckanext.sse import action
from ckanext.sse.validators import (
    coverage_json_object,
    convert_string_to_array,
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
    plugins.implements(plugins.IPackageController, inherit=True)
    plugins.implements(plugins.IValidators)
    plugins.implements(plugins.IActions)
    plugins.implements(plugins.IPackageController, inherit=True)
    plugins.implements(plugins.IResourceController, inherit=True)

    # IConfigurer
    def update_config(self, config_):
        toolkit.add_template_directory(config_, "templates")
        toolkit.add_public_directory(config_, "public")
        toolkit.add_resource("assets", "sse")

    # IPackageController
    def create(self, entity):
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
            "convert_string_to_array": convert_string_to_array,
        }

    # IActions
    def get_actions(self):
        return {
            "package_create": action.package_create,
            "package_update": action.package_update,
            "search_package_list": action.search_package_list,
        }

    # IResourceController
    def after_resource_create(self, context, resource):
        self._sync_dataset_resources_formats_field(resource, context)

    def after_resource_update(self, context, resource):
        self._sync_dataset_resources_formats_field(resource, context)

    def after_resource_delete(self, context, resource):
        self._sync_dataset_resources_formats_field(resource, context)

    def _sync_dataset_resources_formats_field(self, resources, context):
        package_patch_action = toolkit.get_action('package_patch')
        package_show_action = toolkit.get_action('package_show')
        packages_by_id = {}

        if type(resources) is not list:
            resources = [resources]

        for resource in resources:
            package_id = resource.get('package_id')

            if packages_by_id.get(package_id):
                continue

            packages_by_id[package_id] = package_show_action(
                context, dict({'id': package_id}))

            package = packages_by_id[package_id]
            resources_formats = set()

            for resource in package['resources']:
                if resource.get('format'):
                    resources_formats.add(resource.get('format'))
            package['resources_formats'] = list(resources_formats)

        for package_id in packages_by_id.keys():
            package_patch_action(context, packages_by_id[package_id])
