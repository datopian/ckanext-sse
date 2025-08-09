from __future__ import unicode_literals
import json
import datetime
from sqlalchemy import or_
from ckan.common import _, asbool
from ckan.plugins import toolkit as tk
import ckan.lib.uploader as uploader
from ckanext.scheming.helpers import (
    scheming_field_choices,
    scheming_get_dataset_schema,
    scheming_field_by_name,
)
from sqlalchemy import func
import string
import random
from .model import PackageAccessRequest, FormResponse
from .schemas import package_request_access_schema, data_reuse_schema
import os
from ckanext.sse.logic import (
    is_user_id_present_in_the_dict_list,
    reuse_email_notification,
)

from logging import getLogger
import ckan
import ckan.logic
import ckan.lib.navl.dictization_functions as dictization_functions
import ckan.logic as logic
from .logic import (
    mail_allowed_user,
    send_request_mail_to_org_admins,
    mail_rejected_user,
)
from .schemas import package_request_access_schema
import ckan.model as model
import ckanext.activity.helpers as helpers

DataError = dictization_functions.DataError
unflatten = dictization_functions.unflatten


log = getLogger(__name__)


NotFound = ckan.logic.NotFound
NotAuthorized = ckan.logic.NotAuthorized

generic_error_message = {
    "errors": {"auth": [_("Unable to authenticate user")]},
    "error_summary": {_("auth"): _("Unable to authenticate user")},
}


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


@tk.side_effect_free
def resource_activity_list(context, data_dict):
    data_dict["offset"] = None
    data_dict["limit"] = 99999999
    dashboard_activity_list_action = tk.get_action("dashboard_activity_list")
    activities = dashboard_activity_list_action(context, data_dict)
    activity_diff_action = tk.get_action("activity_diff")
    response = []
    for activity in activities:
        if not activity.get("data") or not activity.get("data").get("package"):
            continue
        try:
            diff = activity_diff_action(
                context,
                {
                    "id": activity.get("id"),
                    "object_type": next(iter(activity.get("data"))),
                },
            )
            activity["diff"] = [
                x
                for x in helpers.compare_pkg_dicts(
                    diff.get("activities")[0].get("data").get("package"),
                    diff.get("activities")[1].get("data").get("package"),
                    diff.get("activities")[0].get("id"),
                )
                if "resource" in x.get("type")
            ]
            if len(activity["diff"]):
                response.append(activity)
        except Exception as e:
            log.error(e)
    return response


@tk.chained_action
def package_collaborator_create(up_func, context, data_dict):
    result = up_func(context, data_dict)
    if context.get("send_approval_email"):
        pkg = tk.get_action("package_show")(
            {"ignore_auth": True}, {"id": data_dict.get("id")}
        )

        org_id = pkg.get("organization").get("id")

        package_link = f"{os.environ.get('CKAN_FRONTEND_SITE_URL')}/{pkg.get('organization').get('name')}/{pkg.get('name')}"
        site_title = os.environ.get("CKAN_FRONTEND_SITE_TITLE")
        site_url = os.environ.get("CKAN_FRONTEND_SITE_URL")

        mail_allowed_user(
            data_dict.get("user_id"), pkg, org_id, package_link, site_title, site_url
        )

    return result


@tk.chained_action
def package_collaborator_delete(up_func, context, data_dict):
    result = up_func(context, data_dict)

    pkg = tk.get_action("package_show")(
        {"ignore_auth": True}, {"id": data_dict.get("id")}
    )

    user = tk.get_action("user_show")(
        {"ignore_auth": True, "keep_email": True}, {"id": data_dict.get("user_id")}
    )

    org_id = pkg.get("organization").get("id")

    package_link = f"{os.environ.get('CKAN_FRONTEND_SITE_URL')}/{pkg.get('organization').get('name')}/{pkg.get('name')}"
    site_title = os.environ.get("CKAN_FRONTEND_SITE_TITLE")
    site_url = os.environ.get("CKAN_FRONTEND_SITE_URL")

    email_notification_dict = {
        "user_id": data_dict.get("user_id"),
        "site_url": site_url,
        "site_title": site_title,
        "package_link": package_link,
        "user_name": user.get("full_name")
        or user.get("display_name")
        or user.get("name"),
        "user_email": user.get("email"),
        "package_name": pkg.get("name") or pkg.get("id"),
        "package_title": pkg.get("title") or pkg.get("name") or pkg.get("id"),
        "package_id": pkg.get("id"),
        "org_id": org_id,
    }

    mail_rejected_user(
        email_notification_dict, context.get("revoke_message", ""), "revoked"
    )

    return result


@logic.validate(package_request_access_schema)
@tk.side_effect_free
def request_access_to_dataset(context, data_dict):
    if tk.current_user.is_anonymous:
        raise NotAuthorized
    user = tk.get_action("user_show")(
        {"ignore_auth": True, "keep_email": True}, {"id": tk.current_user.id}
    )

    already_have_access_error = {
        "success": False,
        "errors": {
            "validation": [_("You already have access to the dataset's resources")]
        },
    }

    if user.get("sysadmin") or any(
        user.get("email").lower().endswith("@" + domain.strip())
        for domain in os.environ.get(
            "CKANEXT__SSE__REQUEST_ACCESS_ALLOWED_EMAIL_DOMAINS", ""
        )
        .lower()
        .split(",")
    ):
        return already_have_access_error

    pkg = None

    try:
        pkg = tk.get_action("package_show")(
            context, {"id": data_dict.get("package_id")}
        )
    except tk.ObjectNotFound:
        raise NotFound("Dataset not found")
    except Exception as e:
        log.error(e)
        return {
            "success": False,
            "errors": {"error": [_("Exception retrieving dataset to send mail")]},
            "error_summary": {
                _("error"): _("Exception retrieving dataset to send mail")
            },
        }

    if pkg.get("private"):
        return {
            "success": False,
            "errors": {"validation": [_("Dataset not found or private")]},
        }

    is_user_collaborator_already = is_user_id_present_in_the_dict_list(
        user.get("id"),
        tk.get_action("package_collaborator_list")(
            {"ignore_auth": True}, {"id": pkg.get("id")}
        ),
    )

    if is_user_collaborator_already:
        return already_have_access_error

    is_there_request_access_already_created_for_the_user = (
        PackageAccessRequest.get_by_package_user_and_status(
            pkg.get("id"), user.get("id"), "pending"
        )
    )

    if len(is_there_request_access_already_created_for_the_user) > 0:
        return {
            "success": False,
            "errors": {"validation": [_("Request already created for this resource")]},
        }

    PackageAccessRequest.create(
        package_id=pkg.get("id"),
        user_id=user.get("id"),
        org_id=pkg.get("organization").get("id"),
        message=data_dict.get("message"),
    )

    site_title = os.environ.get("CKAN_FRONTEND_SITE_TITLE")

    email_notification_dict = {
        "user_id": user.get("id"),
        "site_title": site_title,
        "user_name": user.get("full_name")
        or user.get("display_name")
        or user.get("name"),
        "user_email": user.get("email"),
        "package_name": pkg.get("name") or pkg.get("id"),
        "package_title": pkg.get("title") or pkg.get("name") or pkg.get("id"),
        "package_id": pkg.get("id"),
        "user_organization": data_dict.get("user_organization", ""),
        "org_id": pkg.get("organization").get("id"),
        "package_type": pkg.get("type"),
        "message": data_dict.get("message"),
    }

    success = send_request_mail_to_org_admins(email_notification_dict)

    return {
        "success": success,
        "message": (
            "Your request was sent successfully"
            if success
            else "Your request was not registered"
        ),
    }


@tk.chained_action
def package_update(up_func, context, data_dict):
    data_dict = _convert_dct_to_stringify_json(data_dict)
    remove_collaborators_of_package_and_notify_on_restricted_field_change(data_dict)
    result = up_func(context, data_dict)
    return result


def remove_collaborators_of_package_and_notify_on_restricted_field_change(pkg):
    is_restricted = pkg.get("is_restricted")
    if not is_restricted or is_restricted == "True":
        return

    pkg_before_update = tk.get_action("package_show")(
        {"ignore_auth": True}, {"id": pkg.get("id")}
    )

    if not pkg_before_update.get("is_restricted"):
        return

    org_id = pkg_before_update.get("organization").get("id")
    package_link = f"{os.environ.get('CKAN_FRONTEND_SITE_URL')}/{pkg_before_update.get('organization').get('name')}/{pkg.get('name')}"
    site_title = os.environ.get("CKAN_FRONTEND_SITE_TITLE")
    site_url = os.environ.get("CKAN_FRONTEND_SITE_URL")
    pkg_id = pkg_before_update.get("id")

    package_collaborators = tk.get_action("package_collaborator_list")(
        {"ignore_auth": True}, {"id": pkg_id}
    )

    delete_collaborator_action = tk.get_action("package_collaborator_delete")

    user_show_action = tk.get_action("user_show")

    for collaborator in package_collaborators:
        delete_collaborator_action(
            {"ignore_auth": True},
            {"id": pkg_id, "user_id": collaborator.get("user_id")},
        )

        user = user_show_action(
            {"ignore_auth": True, "keep_email": True},
            {"id": collaborator.get("user_id")},
        )

        mail_rejected_user(
            {
                "user_id": user.get("id"),
                "site_url": site_url,
                "site_title": site_title,
                "package_link": package_link,
                "user_name": user.get("full_name")
                or user.get("display_name")
                or user.get("name"),
                "user_email": user.get("email"),
                "package_name": pkg.get("name") or pkg_id,
                "package_title": pkg.get("title") or pkg.get("name") or pkg_id,
                "package_id": pkg_id,
                "org_id": org_id,
                "package_type": pkg.get("type"),
            },
            "",
            "revoked",
        )


def _get_dataset_schema_frequency_options():
    schema = scheming_get_dataset_schema("dataset")
    schema_dataset_fields = schema.get("dataset_fields")
    frequency_field = scheming_field_by_name(schema_dataset_fields, "frequency")
    frequencies = scheming_field_choices(frequency_field)
    return frequencies


def _transform_package_show(package_dict, frequencies, context):
    resources = package_dict.get("resources", [])
    regular_resources = list(
        filter(lambda x: x.get("resource_type") == "regular", resources)
    )
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

    package_dict["last_data_update"] = max_last_modified

    expiration = None
    for f in frequencies:
        value = f.get("value")
        if value == frequency:
            expiration = f.get("expiration")

    is_up_to_date = None
    if expiration is not None and max_last_modified is not None:
        now = datetime.datetime.utcnow()
        last_data_update_date = datetime.datetime.fromisoformat(max_last_modified)
        update_required_after = last_data_update_date + datetime.timedelta(**expiration)
        is_up_to_date = now < update_required_after

    package_dict["is_up_to_date"] = is_up_to_date

    user = context.get("auth_user_obj")
    package_dict["has_access_to_resources"] = True

    if package_dict.get("is_restricted"):
        if not user or user.is_anonymous:
            package_dict["has_access_to_resources"] = False
        else:
            is_sysadmin = user.sysadmin
            is_email_on_the_allowed_domains = any(
                user.email.lower().endswith("@" + domain.strip())
                for domain in os.environ.get(
                    "CKANEXT__SSE__REQUEST_ACCESS_ALLOWED_EMAIL_DOMAINS", ""
                )
                .lower()
                .strip()
                .split(",")
            )
            belong_to_the_dataset_org = is_user_id_present_in_the_dict_list(
                user.id,
                tk.get_action("organization_show")(
                    {"ignore_auth": True},
                    {"id": package_dict.get("organization").get("id")},
                ).get("users"),
            )
            is_already_allowed_to_see_the_dataset = is_user_id_present_in_the_dict_list(
                user.id,
                tk.get_action("package_collaborator_list")(
                    {"ignore_auth": True}, {"id": package_dict.get("id")}
                ),
            )

            if (
                not is_sysadmin
                and not is_email_on_the_allowed_domains
                and not belong_to_the_dataset_org
                and not is_already_allowed_to_see_the_dataset
            ):
                package_dict["has_access_to_resources"] = False

    if not package_dict["has_access_to_resources"]:
        package_dict["resources"] = hide_resources_field(package_dict["resources"])


def user_login(context, data_dict):
    try:
        frontend_secret = os.getenv("CKANEXT__SSE__CLIENT_AUTH_SECRET")
        client_secret = data_dict["client_secret"]

        if frontend_secret != client_secret:
            return {
                "errors": {"auth": [_("Unable to authenticate user")]},
                "error_summary": {
                    _("auth"): _("Client not authorized to authenticate")
                },
            }

        session = context["session"]
        email = data_dict["email"]
        model = context["model"]
        context["ignore_auth"] = True

        if not email:
            return generic_error_message

        user = (
            session.query(model.User)
            .filter(func.lower(model.User.email) == func.lower(email))
            .first()
        )

        if not user:
            password_length = 10
            password = "".join(
                random.choice(string.ascii_letters + string.digits)
                for _ in range(password_length)
            )

            user_name = "".join(
                c.lower() if c.isalnum() else "_" for c in email.split("@")[0]
            )

            user = tk.get_action("user_create")(
                context,
                {
                    "name": user_name,
                    "display_name": data_dict["name"],
                    "fullname": data_dict["name"],
                    "email": email,
                    "password": password,
                    "state": "active",
                },
            )
        else:
            if user.state == "pending":
                user.state = "active"
                session.add(user)
                session.commit()
            elif user.state == "deleted":
                error = {
                    "errors": {"auth": [_("Unable to authenticate user")]},
                    "error_summary": {
                        _("auth"): _(
                            f"User account has been deleted. If you believe this was done in error, please contact support at {os.environ.get('CKANEXT__SSE__ADMINS_EMAIL', 'support@datopian.com')} for assistance."
                        )
                    },
                }

                log.error(error)
                return error
            user = user.as_dict()

        return _generate_token(context, user)
    except Exception as e:
        log.error(e)
        return json.dumps({"error": True})


def _generate_token(context, user):
    context["ignore_auth"] = True
    user["frontend_token"] = None

    try:
        api_tokens = tk.get_action("api_token_list")(context, {"user_id": user["name"]})

        for token in api_tokens:
            if token["name"] == "frontend_token":
                tk.get_action("api_token_revoke")(context, {"jti": token["id"]})

        frontend_token = tk.get_action("api_token_create")(
            context, {"user": user["name"], "name": "frontend_token"}
        )

        user["frontend_token"] = frontend_token.get("token")

    except Exception as e:
        log.error(e)

    return user


@tk.side_effect_free
@tk.chained_action
def package_show(up_func, context, data_dict):
    result = up_func(context, data_dict)
    formats = set()
    for resource in result["resources"]:
        if resource.get("format") and resource.get("resource_type") != "documentation":
            formats.add(resource.get("format"))
    result["format"] = list(formats)

    frequencies = _get_dataset_schema_frequency_options()
    _transform_package_show(result, frequencies, context)

    return result


def hide_resources_field(resources=[]):
    if not resources or len(resources) == 0:
        return []

    for resource in resources:
        if resource.get("resource_type") != "documentation":
            resource["url"] = None

    return resources


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
        _transform_package_show(d, frequencies, context)
    return result


@tk.side_effect_free
def user_extras(context, data_dict):
    current_user = tk.current_user
    if current_user.is_anonymous:
        raise NotAuthorized("Anonymous users are not allowed to use the API")

    user_id = current_user.id
    user = model.User.get(user_id)
    plugin_extras = user.plugin_extras
    ssen_plugin_extras = plugin_extras.get("ssen")

    result = {}
    result["is_verified_user"] = False
    if ssen_plugin_extras and "is_verified_user" in ssen_plugin_extras:
        result["is_verified_user"] = asbool(ssen_plugin_extras["is_verified_user"])

    return result


@logic.validate(data_reuse_schema)
def data_reuse_create(context, data_dict):
    """
    Create a data reuse submission (examples or ideas).

    This is the recommended action for handling both usage examples and ideas.
    Supports more detailed fields for better categorization.
    """
    tk.check_access("data_reuse_create", context, data_dict)

    # Set user_id to current user if not provided and user is logged in
    if not data_dict.get("user_id") and not tk.current_user.is_anonymous:
        data_dict["user_id"] = tk.current_user.id

    try:

        # remove any key fields that are not part of the form data
        form_data = {
            k: v
            for k, v in data_dict.items()
            if k not in ["id", "user_id", "package_id", "reuse_type"]
        }

        upload = uploader.get_uploader("reuse")
        upload.update_data_dict(data_dict, "image_url", "image_upload", "clear_upload")

        upload.upload(uploader.get_max_image_size())

        if form_data.get("image_upload"):
            form_data.pop("image_upload")
            form_data["image_url"] = (
                f"{tk.config.get('ckan.site_url')}/uploads/reuse/{data_dict['image_url']}"
            )

        submission = FormResponse.create(
            type=data_dict["reuse_type"],
            data=form_data,
            user_id=data_dict.get("user_id"),
            package_id=data_dict["package_id"],
            state="pending",
        )
        reuse_email_notification(submission.as_dict(), _type="new")
        return {
            "id": submission.id,
            "form_type": submission.type,
            "data": submission.data,
            "submitted_at": submission.submitted_at.isoformat(),
            "user_id": submission.user_id,
            "package_id": submission.package_id,
        }

    except Exception as e:
        log.error(f"Error creating data reuse submission: {str(e)}")
        raise tk.ValidationError(f"Failed to create data reuse submission: {str(e)}")


@tk.side_effect_free
def data_reuse_list(context, data_dict):
    """
    List data reuse submissions with optional filtering.

    :param package_id: Optional package ID filter
    :param reuse_type: Optional submission type filter ('Example' or 'Idea')
    :param label: Optional label filter
    :param organisation_type: Optional organisation type filter
    :param showcase_approved: Optional filter for showcase approved submissions
    :param limit: Optional limit (default 100)
    :param offset: Optional offset (default 0)
    :param include_dataset Optional to include the dataset dict
    :return: List of data reuse submissions


    """
    tk.check_access("data_reuse_list", context, data_dict)

    reuse_type = data_dict.get("reuse_type")
    limit = int(data_dict.get("limit", 100))
    offset = int(data_dict.get("offset", 0))
    include_all = tk.asbool(data_dict.get("include_all", False))
    include_dataset = tk.asbool(data_dict.get("include_dataset", False))

    if reuse_type:
        submissions = FormResponse.get_by_form_type(reuse_type, include_all=include_all)
    else:
        submissions = FormResponse.get_all(include_all=include_all)

    total_count = len(submissions)
    submissions = submissions[offset : offset + limit]
    result = []
    for submission in submissions:
        submission_dict = submission.as_dict()
        if include_dataset and submission.package_id:
            submission_dict["dataset"] = tk.get_action("package_show")(
                context, {"id": submission.package_id}
            )
        result.append(submission_dict)

    return {
        "data": result,
        "count": len(result),
        "total_count": total_count,
        "limit": limit,
        "offset": offset,
    }


@tk.side_effect_free
def data_reuse_show(context, data_dict):
    """
    Show a specific data reuse submission by ID.

    :param id: The ID of the submission to retrieve
    :return: The data reuse submission details
    """
    tk.check_access("data_reuse_show", context, data_dict)
    id = tk.get_or_bust(data_dict, "id")
    include_all = tk.asbool(data_dict.get("include_all", False))
    include_dataset = tk.asbool(data_dict.get("include_dataset", False))

    submission = FormResponse.get(id, include_all=include_all)
    if not submission:
        raise tk.ObjectNotFound("Data reuse submission not found")

    submission_dict = submission.as_dict()
    if include_dataset and submission.package_id:
        submission_dict["dataset"] = tk.get_action("package_show")(
            context, {"id": submission.package_id}
        )
    return submission_dict


@logic.validate(data_reuse_schema)
def data_reuse_update(context, data_dict):
    """
    Update an existing data reuse submission.

    :param id: The ID of the submission to update
    :return: The updated submission details
    """
    tk.check_access("data_reuse_update", context, data_dict)

    id = tk.get_or_bust(data_dict, "id")

    submission = FormResponse.get(id, include_all=True)
    if not submission:
        raise tk.ObjectNotFound("Data reuse submission not found")

    # Remove any key fields that are not part of the form data
    form_data = {
        k: v
        for k, v in data_dict.items()
        if k not in ["id", "user_id", "package_id", "reuse_type"]
    }

    try:
        upload = uploader.get_uploader("reuse")
        upload.update_data_dict(data_dict, "image_url", "image_upload", "clear_upload")

        upload.upload(uploader.get_max_image_size())

        if form_data.get("image_upload"):
            form_data.pop("image_upload")
            form_data["image_url"] = (
                f"{tk.config.get('ckan.site_url')}/uploads/reuse/{data_dict['image_url']}"
            )

        updated_submission = FormResponse.update(id, **form_data)

        return {
            "id": updated_submission.id,
            "type": updated_submission.type,
            "data": updated_submission.data,
            "submitted_at": updated_submission.submitted_at.isoformat(),
            "user_id": updated_submission.user_id,
            "package_id": updated_submission.package_id,
        }

    except Exception as e:
        log.error(f"Error updating data reuse submission: {str(e)}")
        raise tk.ValidationError(f"Failed to update data reuse submission: {str(e)}")


def data_reuse_patch(context, data_dict):
    """
    Patch an existing data reuse submission.
    """
    tk.check_access("data_reuse_update", context, data_dict)

    id = tk.get_or_bust(data_dict, "id")
    feedback = data_dict.get("feedback")

    existing_dict = tk.get_action("data_reuse_show")(
        context, {"id": id, "include_all": True}
    )
    patched_dict = dict(existing_dict)
    patched_dict.update(data_dict)

    old_state = existing_dict.get("state")
    new_state = data_dict.get("state")

    submission = FormResponse.update(id, **patched_dict)
    if old_state == "pending" and new_state in ["approved", "rejected"]:
        reuse_email_notification(submission.as_dict(), _type=new_state, feedback=feedback)

    return submission.as_dict()


def data_reuse_delete(context, data_dict):
    """
    Delete a data reuse submission.

    :param id: The ID of the submission to delete
    :return: Success confirmation
    """
    tk.check_access("data_reuse_delete", context, data_dict)

    id = tk.get_or_bust(data_dict, "id")

    submission = FormResponse.get(id)
    if not submission:
        raise tk.ObjectNotFound("Data reuse submission not found")

    try:
        success = FormResponse.delete(id)
        if success:
            return {
                "id": id,
                "success": True,
                "message": "Data reuse submission deleted successfully",
            }
        else:
            raise tk.ValidationError("Failed to delete data reuse submission")

    except Exception as e:
        log.error(f"Error deleting data reuse submission: {str(e)}")
        raise tk.ValidationError(f"Failed to delete data reuse submission: {str(e)}")
