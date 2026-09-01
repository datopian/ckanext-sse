from typing import cast

import ckan.lib.base as base
import ckan.logic as logic
import ckan.model as model
from ckan.common import _, asbool, current_user, request
from ckan.lib.helpers import helper_functions as h
from ckan.types import Context
from flask import Blueprint

from ckanext.sse import account_lifecycle, password_policy

blueprint = Blueprint("ssen-admin", __name__, url_prefix="/ckan-admin")


def _require_sysadmin():
    """These pages list and act on disabled accounts, so gate them tightly."""
    if (current_user is None or current_user.is_anonymous
            or not getattr(current_user, "sysadmin", False)):
        return base.abort(403, _("Need to be a system administrator to "
                                 "manage this."))
    return None


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


def _ssen(user):
    return (user.plugin_extras or {}).get("ssen") or {}


def reactivate_users_index() -> str:
    denied = _require_sysadmin()
    if denied is not None:
        return denied
    disabled = account_lifecycle.inactivity_disabled_users()
    requested = [u.name for u in disabled if _ssen(u).get("reactivation_requested_at")]
    data = dict(
        disabled_users=[u.name for u in disabled],
        requested_users=requested,
    )
    return base.render("admin/reactivate-users.html", extra_vars=data)


def reactivate_user():
    denied = _require_sysadmin()
    if denied is not None:
        return denied
    username = request.form.get("username")
    user = account_lifecycle.reactivate(username)
    if user is None:
        return base.abort(404, _("User not found"))
    h.flash_success(_("Reactivated {}".format(user.name)))
    return h.redirect_to("ssen-admin.reactivate_users_index")


blueprint.add_url_rule(
    "/reactivate-users", methods=["GET"], view_func=reactivate_users_index
)
blueprint.add_url_rule(
    "/reactivate-users", methods=["POST"], view_func=reactivate_user
)


def force_expire_index() -> str:
    denied = _require_sysadmin()
    if denied is not None:
        return denied
    return base.render("admin/force-expire.html", extra_vars={})


def force_expire_password():
    denied = _require_sysadmin()
    if denied is not None:
        return denied
    username = request.form.get("username")
    user = password_policy.force_expire(username)
    if user is None:
        h.flash_error(
            _("No local password to expire for {} (an SSO-only account has "
              "none).").format(username or _("that user")))
    else:
        h.flash_success(
            _("{} will be required to change their password at next "
              "sign-in.").format(user.name))
    return h.redirect_to("ssen-admin.force_expire_index")


blueprint.add_url_rule(
    "/force-expire-password", methods=["GET"], view_func=force_expire_index
)
blueprint.add_url_rule(
    "/force-expire-password", methods=["POST"], view_func=force_expire_password
)

