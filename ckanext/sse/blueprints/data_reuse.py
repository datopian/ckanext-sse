import logging
from typing import cast

import ckan.lib.base as base
import ckan.logic as logic
import ckan.model as model
from ckan.lib.helpers import helper_functions as h
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


@blueprint.route("/submit/<package_id>", methods=["GET", "POST"])
def submit_form(package_id):
    """Submit a data reuse form for a specific dataset"""
    context = _get_context()

    # Verify package exists
    try:
        package = tk.get_action("package_show")(context, {"id": package_id})
    except logic.NotFound:
        return base.abort(404, tk._("Dataset not found"))
    except logic.NotAuthorized:
        return base.abort(403, tk._("Not authorized to view this dataset"))

    if tk.request.method == "POST":
        try:
            # Get form data
            form_data = dict(tk.request.form)
            form_data["package_id"] = package_id

            # Add user_id if user is logged in
            if tk.current_user:
                form_data["user_id"] = tk.current_user.id

            # Create the data reuse submission
            result = tk.get_action("data_reuse_create")(context, form_data)

            h.flash_success(
                tk._(
                    "Thank you for your submission! Your {} has been recorded.".format(
                        form_data.get("submission_type", "submission").lower()
                    )
                )
            )

            return redirect(url_for("dataset.read", id=package_id))

        except logic.ValidationError as e:
            errors = e.error_dict
            h.flash_error(tk._("Please correct the errors below"))
        except logic.NotAuthorized:
            return base.abort(403, tk._("Not authorized to submit data reuse form"))
        except Exception as e:
            log.error("Error submitting data reuse form: %s", str(e))
            h.flash_error(
                tk._("An error occurred while submitting your form. Please try again.")
            )
            errors = {}
    else:
        errors = {}
        form_data = {"package_id": package_id}

    # Get choices for dropdowns - format for CKAN form macros
    label_choices = [
        {"value": "", "text": tk._("Select a category")},
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
    submission_type_choices = [
        {"value": "", "text": tk._("Select submission type")},
        {"value": "Example", "text": tk._("Example")},
        {"value": "Idea", "text": tk._("Idea")},
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
        "package": package,
        "data": form_data,
        "errors": errors,
        "label_choices": label_choices,
        "organisation_type_choices": organisation_type_choices,
        "submission_type_choices": submission_type_choices,
        "showcase_permission_choices": showcase_permission_choices,
        "contact_permission_choices": contact_permission_choices,
    }

    return base.render("data_reuse/submit_form.html", extra_vars=extra_vars)


@blueprint.route("/list")
def list_submissions():
    """List all data reuse submissions with filtering by submission type"""
    context = _get_context()

    try:
        logic.check_access("data_reuse_list", context, {})
    except logic.NotAuthorized:
        return base.abort(403, tk._("Not authorized to view data reuse submissions"))

    # Get query parameters for filtering
    submission_type = tk.request.args.get("submission_type", "")
    page = int(tk.request.args.get("page", 1))
    limit = int(tk.request.args.get("limit", 20))

    # Calculate offset from page number
    offset = (page - 1) * limit

    # Build filter parameters - only submission_type filter
    filter_params = {}
    if submission_type:
        filter_params["submission_type"] = submission_type

    filter_params["offset"] = offset
    filter_params["limit"] = limit

    try:
        # Get submissions
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
            "submission_type": submission_type,
            "submission_types": submission_types,
            "package_names": package_names,
        }

        return base.render("data_reuse/list_submissions.html", extra_vars=extra_vars)

    except Exception as e:
        log.error("Error listing data reuse submissions: %s", str(e))
        h.flash_error(tk._("An error occurred while loading submissions"))
        return base.render(
            "data_reuse/list_submissions.html",
            extra_vars={
                "submissions": [],
                "total_count": 0,
                "page": page,
                "limit": limit,
                "total_pages": 0,
                "submission_type": submission_type,
                "submission_types": ["Example", "Idea"],  # Default submission types
                "package_names": {},
            },
        )


@blueprint.route("/view/<submission_id>")
def view_submission(submission_id):
    """View a specific data reuse submission"""
    context = _get_context()

    try:
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

        return base.render("data_reuse/view_submission.html", extra_vars=extra_vars)

    except logic.NotFound:
        return base.abort(404, tk._("Submission not found"))
    except logic.NotAuthorized:
        return base.abort(403, tk._("Not authorized to view this submission"))
    except Exception as e:
        log.error("Error viewing submission: %s", str(e))
        h.flash_error(tk._("An error occurred while loading the submission"))
        return redirect(url_for("data_reuse.list_submissions"))


@blueprint.route("/delete/<submission_id>", methods=["POST"])
def delete_submission(submission_id):
    """Delete a data reuse submission"""
    context = _get_context()

    try:
        tk.get_action("data_reuse_delete")(context, {"id": submission_id})
        h.flash_success(tk._("Submission deleted successfully"))
    except logic.NotFound:
        h.flash_error(tk._("Submission not found"))
    except logic.NotAuthorized:
        h.flash_error(tk._("Not authorized to delete this submission"))
    except Exception as e:
        log.error("Error deleting submission: %s", str(e))
        h.flash_error(tk._("An error occurred while deleting the submission"))

    return redirect(url_for("data_reuse.list_submissions"))
