import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
from ckanext.sse import action
from ckanext.sse.validators import (
    coverage_json_object,
    resource_type_validator,
    schema_json_object,
    schema_output_string_json,
    ib1_trust_framework_validator,
    ib1_sensitivity_class_validator,
    ib1_dataset_assurance_validator,
)


class SsePlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IValidators)
    plugins.implements(plugins.IActions)

    # IConfigurer
    def update_config(self, config_):
        toolkit.add_template_directory(config_, "templates")
        toolkit.add_public_directory(config_, "public")
        toolkit.add_resource("assets", "sse")

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
            "search_package_list": action.search_package_list,
        }
