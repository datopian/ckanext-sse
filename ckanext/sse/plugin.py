import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
from ckanext.sse.validators import (
    coverage_json_object,
    resource_type, 
    schema_json_object
)

class SsePlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IValidators)
    
    # IConfigurer
    def update_config(self, config_):
        toolkit.add_template_directory(config_, "templates")
        toolkit.add_public_directory(config_, "public")
        toolkit.add_resource("assets", "sse")

    # IValidators
    def get_validators(self):
        return {
            'coverage_json_object': coverage_json_object,
            'schema_json_object': schema_json_object,
            'resource_type': resource_type
        }
