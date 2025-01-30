import json
import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import logging
from ckanext.sse import action
import ckan.authz
import ckanext.sse.controllers.user_group as user_group
import ckanext.sse.activity as activity
import ckanext.sse.auth.package as auth
from ckan import logic, model, plugins
from ckanext.sse.validators import (
    coverage_json_object,
    resource_type_validator,
    schema_json_object,
    schema_output_string_json,
    ib1_trust_framework_validator,
    ib1_sensitivity_class_validator,
    ib1_dataset_assurance_validator,
)
import ckanext.sse.signals as signals

log = logging.getLogger(__name__)

class SsePlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IValidators)
    plugins.implements(plugins.IActions)
    plugins.implements(plugins.IPackageController, inherit=True)
    plugins.implements(plugins.IBlueprint)
    plugins.implements(plugins.IAuthFunctions)
    plugins.implements(plugins.ISignal, inherit=True)
    plugins.implements(plugins.IPermissionLabels)

    # IPermissionLabels
    def get_dataset_labels(self, dataset_obj: model.Package) -> list[str]:
        if dataset_obj.state == u'active' and not dataset_obj.private:
            return [u'public']
        if ckan.authz.check_config_permission('allow_dataset_collaborators'):
            # Add a generic label for all this dataset collaborators
            labels = [u'collaborator-%s' % dataset_obj.id]
        else:
            labels = []
        groups = dataset_obj.get_groups('user group')
        
        for group in groups:
            labels.append(u'user-group-%s' % group.id)

        if dataset_obj.owner_org:
            labels.append(u'member-%s' % dataset_obj.owner_org)
        else:
            labels.append(u'creator-%s' % dataset_obj.creator_user_id)

        return labels

    # IPermissionLabels
    def get_user_dataset_labels(self, user_obj: model.User) -> list[str]:
        labels = [u'public']
        if not user_obj or user_obj.is_anonymous:
            return labels
        user_groups = toolkit.get_action('group_list_authz')({
            u'user': user_obj.name,
            u'for_view': True,
            u'auth_user_obj': user_obj,
            u'use_cache': False
        })

        filtered_groups = [
            group for group in user_groups if group['type'] == 'user group']

        labels.append(u'creator-%s' % user_obj.id)

        orgs = logic.get_action(u'organization_list_for_user')(
            {u'user': user_obj.id}, {u'permission': u'read'})
        labels.extend(u'member-%s' % o[u'id'] for o in orgs)
        labels.extend(u'user-group-%s' % o[u'id'] for o in filtered_groups)

        if ckan.authz.check_config_permission('allow_dataset_collaborators'):
            # Add a label for each dataset this user is a collaborator of
            datasets = logic.get_action('package_collaborator_list_for_user')(
                {'ignore_auth': True}, {'id': user_obj.id})

            labels.extend('collaborator-%s' %
                          d['package_id'] for d in datasets)

        return labels
    
    # IAuthFunctions
    def get_auth_functions(self):
        return {
            "package_show": auth.custom_package_show
        }

    # IBlueprint
    def get_blueprint(self):
        return user_group.blueprint

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

    # IPackageController
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
            "package_search": action.package_search,
            "daily_report_activity": activity.dashboard_activity_list_for_all_users,
            "search_package_list": action.search_package_list,
        }

    # ISignal
    def get_signal_subscriptions(self):
        return signals.get_subscriptions()
