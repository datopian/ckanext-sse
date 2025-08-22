import json
import logging

import ckan.authz
import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import logging
from ckanext.sse import action, auth
import ckan.authz
from ckanext.sse.blueprints import dataset, request_access_dashboard, admin, data_reuse
from .model import PackageAccessRequest, FormResponse
import ckanext.sse.activity as activity
from ckanext.sse.helpers import (
    is_org_admin_by_package_id,
    is_admin_of_any_org,
    get_data_reuse_field_labels,
)
from ckan import logic, model, plugins
from .utils import update_resource_extra
import ckanext.sse.signals as signals
from ckanext.sse import action
from ckanext.sse.validators import (
    coverage_json_object,
    ib1_dataset_assurance_validator,
    ib1_sensitivity_class_validator,
    ib1_trust_framework_validator,
    resource_type_validator,
    schema_json_object,
    schema_output_string_json,
)

log = logging.getLogger(__name__)

class SsePlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IValidators)
    plugins.implements(plugins.ITemplateHelpers)
    plugins.implements(plugins.IActions)
    plugins.implements(plugins.IAuthFunctions)
    plugins.implements(plugins.IPackageController, inherit=True)
    plugins.implements(plugins.IConfigurable, inherit=True)
    plugins.implements(plugins.IBlueprint)
    plugins.implements(plugins.ISignal, inherit=True)
    plugins.implements(plugins.IPermissionLabels)
    plugins.implements(plugins.IResourceController, inherit=True)

    # IPermissionLabels
    def get_dataset_labels(self, dataset_obj: model.Package) -> list[str]:
        if dataset_obj.state == "active" and not dataset_obj.private:
            return ["public"]
        if ckan.authz.check_config_permission("allow_dataset_collaborators"):
            # Add a generic label for all this dataset collaborators
            labels = ["collaborator-%s" % dataset_obj.id]
        else:
            labels = []

        groups = dataset_obj.get_groups("user_group")

        for group in groups:
            labels.append("user-group-%s" % group.id)

        if dataset_obj.owner_org:
            labels.append("member-%s" % dataset_obj.owner_org)
        else:
            labels.append("creator-%s" % dataset_obj.creator_user_id)

        return labels

    # IConfigurable
    def configure(self, config_):
        from ckan.model import meta
        if not PackageAccessRequest.__table__.exists(meta.engine):
            PackageAccessRequest.__table__.create(meta.engine)
        if not FormResponse.__table__.exists(meta.engine):
            FormResponse.__table__.create(meta.engine)

    # ITemplateHelpers
    def get_helpers(self):
        return {
                    'is_org_admin_by_package_id': is_org_admin_by_package_id,
        'is_admin_of_any_org': is_admin_of_any_org,
        'get_data_reuse_field_labels': get_data_reuse_field_labels,
        }

    # IPermissionLabels
    def get_user_dataset_labels(self, user_obj: model.User) -> list[str]:
        labels = ["public"]
        if not user_obj or user_obj.is_anonymous:
            return labels
        user_groups = toolkit.get_action("group_list_authz")(
            {
                "user": user_obj.name,
                "for_view": True,
                "auth_user_obj": user_obj,
                "use_cache": False,
            }
        )

        filtered_groups = [
            group for group in user_groups if group["type"] == "user_group"
        ]

        labels.append("creator-%s" % user_obj.id)

        orgs = logic.get_action("organization_list_for_user")(
            {"user": user_obj.id}, {"permission": "read"}
        )
        labels.extend("member-%s" % o["id"] for o in orgs)
        labels.extend("user-group-%s" % o["id"] for o in filtered_groups)

        if ckan.authz.check_config_permission("allow_dataset_collaborators"):
            # Add a label for each dataset this user is a collaborator of
            datasets = logic.get_action("package_collaborator_list_for_user")(
                {"ignore_auth": True}, {"id": user_obj.id}
            )

            labels.extend("collaborator-%s" % d["package_id"] for d in datasets)

        return labels

    # IBlueprint
    def get_blueprint(self):
        return [dataset.blueprint, *request_access_dashboard.get_blueprints(), admin.blueprint, data_reuse.blueprint]

    # IConfigurer
    def update_config(self, config_):
        toolkit.add_template_directory(config_, "templates")
        toolkit.add_public_directory(config_, "public")
        toolkit.add_resource("assets", "sse")

    # IPackageController
    def create(self, entity):
        if entity.type == "showcase":
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
        if entity.type == "showcase":
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
    def before_dataset_search(self, data_dict):
        data_dict["qf"] = "text_ngram"
        return data_dict


    def before_dataset_index(self, data_dict):
        if data_dict.get("coverage", False):
            data_dict["coverage"] = json.dumps(data_dict["coverage"])
        if data_dict.get("format"):
            data_dict["format"] = json.dumps(data_dict["format"])

        dataset = json.loads(data_dict.get("data_dict"))
        resources = dataset.get("resources", [])
        has_geospatial_data = False
        has_geospatial_datastore_active = False
        has_datastore_active = False
        for resource in resources:
            is_geospatial = resource.get("is_geospatial", False)
            datastore_active = resource.get("datastore_active", False)
            
            if not has_datastore_active and datastore_active:
                has_datastore_active = True

            if is_geospatial:
                if not has_geospatial_data:
                    has_geospatial_data = True

                if datastore_active and not has_geospatial_datastore_active:
                    has_geospatial_datastore_active = True

        data_dict["has_geospatial_data"] = has_geospatial_data
        data_dict["has_geospatial_datastore_active"] = has_geospatial_datastore_active
        data_dict["has_datastore_active"] = has_datastore_active

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
            "resource_activity_list": action.resource_activity_list,
            "package_collaborator_create": action.package_collaborator_create,
            "package_collaborator_delete": action.package_collaborator_delete,
            "request_access_to_dataset": action.request_access_to_dataset,
            "package_update": action.package_update,
            "package_show": action.package_show,
            "user_login": action.user_login,
            "package_search": action.package_search,
            "daily_report_activity": activity.dashboard_activity_list_for_all_users,
            "search_package_list": action.search_package_list,
            "user_extras": action.user_extras,
            "data_reuse_create": action.data_reuse_create,
            "data_reuse_list": action.data_reuse_list,
            "data_reuse_show": action.data_reuse_show,
            "data_reuse_update": action.data_reuse_update,
            "data_reuse_patch": action.data_reuse_patch,
            "data_reuse_delete": action.data_reuse_delete
        }

    # IAuthFunctions
    def get_auth_functions(self):
        return {
            "data_reuse_create": auth.data_reuse_create,
            "data_reuse_list": auth.data_reuse_list,
            "data_reuse_show": auth.data_reuse_show,
            "data_reuse_update": auth.data_reuse_update,
            "data_reuse_delete": auth.data_reuse_delete,
        }

    # ISignal
    def get_signal_subscriptions(self):
        return signals.get_subscriptions()

    # IResourceController
    def after_resource_create(self, context, data_dict):
        id = data_dict.get("id")
        format = data_dict.get("format")
        if format.lower() == "geojson":
            update_resource_extra(id, "is_geospatial", "True")
        return data_dict
