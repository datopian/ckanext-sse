import logging
from typing import cast

import ckan.logic as logic
import ckan.model as model
import ckan.lib.navl.dictization_functions as dict_fns

from ckan.types import Context
from flask import Blueprint, redirect, url_for
import ckan.plugins.toolkit as tk

log = logging.getLogger(__name__)

blueprint = Blueprint("data_reuse", __name__, url_prefix="/dataset/reuse")


def _get_context():
    """Get the context for API calls"""
    return cast(
        Context,
        {
            "model": model,
            "session": model.Session,
            "user": tk.current_user.name if tk.current_user else None,
            "auth_user_obj": tk.current_user,
        },
    )


@blueprint.route("/<reuse_type>/submit/<package_id>", methods=["GET", "POST"])
def submit_data_reuse(
    reuse_type,
    package_id,
):
    """Submit a data reuse form for a specific dataset"""
    context = _get_context()

    # Verify package exists
    try:
        package = tk.get_action("package_show")(context, {"id": package_id})
    except tk.ObjectNotFound:
        return tk.abort(404, tk._("Dataset not found"))
    except tk.NotAuthorized:
        return tk.abort(403, tk._("Not authorized to view this dataset"))
    if tk.request.method == "POST":
        try:
            # Get form data
            form_data = logic.clean_dict(
                dict_fns.unflatten(
                    logic.tuplize_dict(logic.parse_params(tk.request.form))
                )
            )
            form_data.update(
                logic.clean_dict(
                    dict_fns.unflatten(
                        logic.tuplize_dict(logic.parse_params(tk.request.files))
                    )
                )
            )

            form_data["package_id"] = package_id

            # Add user_id if user is logged in
            if tk.current_user:
                form_data["user_id"] = tk.current_user.id

            form_data["reuse_type"] = reuse_type

            # Create the data reuse submission
            result = tk.get_action("data_reuse_create")(context, form_data)

            # Render success page directly
            extra_vars = {
                "package": package,
                "reuse_type": reuse_type,
                "submission_title": form_data.get("title", ""),
            }
            return tk.render(
                "data_reuse/submission_success.html", extra_vars=extra_vars
            )

        except tk.ValidationError as e:
            errors = e.error_dict
            tk.h.flash_error(tk._("Please correct the errors below", errors))
        except tk.NotAuthorized:
            return tk.abort(403, tk._("Not authorized to submit data reuse form"))
        except Exception as e:
            log.error("Error submitting data reuse form: %s", str(e))
            tk.h.flash_error(
                tk._("An error occurred while submitting your form. Please try again.")
            )
            errors = {}
    else:
        errors = {}
        form_data = {"package_id": package_id}

    # Get choices for dropdowns - format for CKAN form macros
    label_choices = [
        {"value": "", "text": tk._("Select a label")},
        {"value": "Community Support", "text": tk._("Community Support")},
        {"value": "Research Innovation", "text": tk._("Research Innovation")},
        {"value": "Sustainability", "text": tk._("Sustainability")},
    ]
    organisation_type_choices = [
        {"value": "", "text": tk._("Select organisation type")},
        {"value": "Academic", "text": tk._("Academic")},
        {"value": "Construction", "text": tk._("Construction")},
        {"value": "Data Science", "text": tk._("Data Science")},
        {"value": "Energy Consultant", "text": tk._("Energy Consultant")},
        {"value": "Energy Utility", "text": tk._("Energy Utility")},
        {"value": "Government", "text": tk._("Government")},
        {"value": "Innovator", "text": tk._("Innovator")},
        {"value": "Local Authority", "text": tk._("Local Authority")},
        {"value": "Regulator", "text": tk._("Regulator")},
        {"value": "Technology", "text": tk._("Technology")},
        {"value": "Other", "text": tk._("Other")},
    ]

    showcase_permission_choices = [
        {"value": "", "text": tk._("Select permission")},
        {"value": "Yes", "text": tk._("Yes")},
        {"value": "No", "text": tk._("No")},
        {"value": "Others", "text": tk._("Others")},
    ]
    contact_permission_choices = [
        {"value": "", "text": tk._("Select permission")},
        {"value": "Yes", "text": tk._("Yes")},
        {"value": "No", "text": tk._("No")},
    ]

    extra_vars = {
        "reuse_type": reuse_type,
        "package": package,
        "data": form_data,
        "errors": errors,
        "label_choices": label_choices,
        "organisation_type_choices": organisation_type_choices,
        "showcase_permission_choices": showcase_permission_choices,
        "contact_permission_choices": contact_permission_choices,
    }

    return tk.render("data_reuse/submit_form.html", extra_vars=extra_vars)


@blueprint.route("/list")
def list_data_reuse():
    """List all data reuse submissions with filtering by submission type"""
    context = _get_context()

    try:
        tk.check_access("data_reuse_list", context, {})
    except tk.NotAuthorized:
        return tk.abort(403, tk._("Not authorized to view data reuse submissions"))

    # Get query parameters for filtering
    reuse_type = tk.request.args.get("reuse_type", "")
    page = int(tk.request.args.get("page", 1))
    limit = int(tk.request.args.get("limit", 20))

    # Calculate offset from page number
    offset = (page - 1) * limit

    # Build filter parameters - only submission_type filter
    filter_params = {}
    if reuse_type:
        filter_params["reuse_type"] = reuse_type

    filter_params["offset"] = offset
    filter_params["limit"] = limit

    try:
        # Get submissions
        context.update({"include_all": True})
        result = tk.get_action("data_reuse_list")(context, filter_params)
        submissions = result.get("data", [])
        total_count = result.get("total_count", 0)

        # Calculate pagination
        total_pages = (total_count + limit - 1) // limit

        # Get unique values for filter dropdowns
        all_submissions = tk.get_action("data_reuse_list")(context, {"limit": 1000})
        all_submission_data = all_submissions.get("data", [])

        # Debug: log the submissions data
        log.debug("Total submissions found: %s", len(all_submission_data))
        for i, sub in enumerate(all_submission_data[:5]):  # Log first 5 for debugging
            log.debug("Submission %s: %s", i, sub.get("submission_type"))

        # Get unique submission types and sort them
        submission_types = list(
            set(
                [
                    s.get("submission_type")
                    for s in all_submission_data
                    if s.get("submission_type")
                ]
            )
        )
        # Add fallback types if no submissions exist yet
        if not submission_types:
            submission_types = ["Example", "Idea"]
        else:
            submission_types.sort()  # Sort alphabetically
        log.debug("Available submission types: %s", submission_types)

        # Get package names for display
        package_names = {}
        for submission in submissions:
            if (
                submission.get("package_id")
                and submission["package_id"] not in package_names
            ):
                try:
                    pkg = tk.get_action("package_show")(
                        context, {"id": submission["package_id"]}
                    )
                    package_names[submission["package_id"]] = pkg.get(
                        "title", pkg.get("name", "")
                    )
                except:
                    package_names[submission["package_id"]] = "Unknown Dataset"

        extra_vars = {
            "submissions": submissions,
            "total_count": total_count,
            "page": page,
            "limit": limit,
            "total_pages": total_pages,
            "reuse_type": reuse_type,
            "reuse_type_options": ["example", "idea"],
            "package_names": package_names,
        }

        return tk.render("data_reuse/list_submissions.html", extra_vars=extra_vars)

    except Exception as e:
        log.error("Error listing data reuse submissions: %s", str(e))
        tk.h.flash_error(tk._("An error occurred while loading submissions"))
        return tk.render(
            "data_reuse/list_submissions.html",
            extra_vars={
                "submissions": [],
                "total_count": 0,
                "page": page,
                "limit": limit,
                "total_pages": 0,
                "submission_type": reuse_type,
                "reuse_type_options": ["example", "idea"],
                "package_names": {},
            },
        )


@blueprint.route("/view/<submission_id>")
def view_data_reuse(submission_id):
    """View a specific data reuse submission"""
    context = _get_context()

    try:
        context.update({"include_all": True})
        submission = tk.get_action("data_reuse_show")(context, {"id": submission_id})

        # Get package details if available
        package = None
        if submission.get("package_id"):
            try:
                package = tk.get_action("package_show")(
                    context, {"id": submission["package_id"]}
                )
            except:
                pass

        extra_vars = {
            "submission": submission,
            "package": package,
        }

        return tk.render("data_reuse/view_submission.html", extra_vars=extra_vars)

    except tk.ObjectNotFound:
        return tk.abort(404, tk._("Submission not found"))
    except tk.NotAuthorized:
        return tk.abort(403, tk._("Not authorized to view this submission"))
    except Exception as e:
        log.error("Error viewing submission: %s", str(e))
        tk.h.flash_error(tk._("An error occurred while loading the submission"))
        return redirect(url_for("data_reuse.list_data_reuse"))


@blueprint.route("/delete/<submission_id>", methods=["POST"])
def delete_data_reuse(submission_id):
    """Delete a data reuse submission"""
    context = _get_context()

    try:
        tk.get_action("data_reuse_delete")(context, {"id": submission_id})
        tk.h.flash_success(tk._("Submission deleted successfully"))
    except tk.ObjectNotFound:
        tk.h.flash_error(tk._("Submission not found"))
    except tk.NotAuthorized:
        tk.h.flash_error(tk._("Not authorized to delete this submission"))
    except Exception as e:
        log.error("Error deleting submission: %s", str(e))
        tk.h.flash_error(tk._("An error occurred while deleting the submission"))

    return redirect(url_for("data_reuse.list_data_reuse"))
