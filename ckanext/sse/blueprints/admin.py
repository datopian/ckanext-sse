from typing import cast

import ckan.lib.base as base
import ckan.logic as logic
import ckan.model as model
from ckan.common import _, asbool, current_user, request
from ckan.lib.helpers import helper_functions as h
from ckan.types import Context
from flask import Blueprint

blueprint = Blueprint("ssen-admin", __name__, url_prefix="/ckan-admin")


def _get_verified_users():
    q = model.Session.query(model.User).filter(
        model.User.plugin_extras["ssen"]["is_verified_user"].astext == "true",
        model.User.state == "active",
    )
    return q


def verified_users_index() -> str:
    data = dict(verified_users=[a.name for a in _get_verified_users()])
    return base.render("admin/verified-users.html", extra_vars=data)


def verified_users():
    username = request.form.get("username")
    status = asbool(request.form.get("status"))

    try:
        context = cast(
            Context,
            {
                "model": model,
                "session": model.Session,
                "user": current_user.name,
                "auth_user_obj": current_user,
            },
        )
        data_dict = {"id": username, "plugin_extras": { "ssen": { "is_verified_user": status } }}
        user = logic.get_action("user_patch")(context, data_dict)
    except logic.NotAuthorized:
        return base.abort(403, _("Not authorized to promote user to verified user"))
    except logic.NotFound:
        return base.abort(404, _("User not found"))

    if status:
        h.flash_success(_("Promoted {} to verified user".format(user["display_name"])))
    else:
        h.flash_success(
            _("Revoked verified user permission from {}".format(user["display_name"]))
        )
    return h.redirect_to("ssen-admin.verified_users_index")


blueprint.add_url_rule(
    "/verified-users", methods=["GET"], view_func=verified_users_index
)

blueprint.add_url_rule(rule=u'/verified-users', view_func=verified_users, methods=['POST'])

