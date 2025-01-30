import ckan.plugins.toolkit as toolkit
from ckan.common import _
import ckan.model as model
import logging
import ckan.lib.base as base
import ckan.logic as logic
from flask import Blueprint, request
from ckan.lib.helpers import helper_functions as helpers
from ckan.common import current_user
from ckan.types import Context
from typing import Any

NotFound = logic.NotFound
NotAuthorized = logic.NotAuthorized

log = logging.getLogger(__name__)

blueprint = Blueprint('user_groups', __name__)


def _prepare(id: str) -> tuple[Context, dict[str, Any]]:
    context: Context = {
        u'user': current_user.name,
        u'for_view': True,
        u'auth_user_obj': current_user,
        u'use_cache': False
    }

    try:
        pkg_dict = toolkit.get_action(u'package_show')(
            context, {u'id': id, 'group_type': 'user group'})
    except (NotFound, NotAuthorized):
        return base.abort(404, _(u'Dataset not found'))
    return context, pkg_dict


@blueprint.route("/dataset/user_groups/<id>", methods=["GET", "POST"])
def user_groups(id):
    """user_groups tab controller."""
    context, pkg_dict = _prepare(id)

    if request.method == 'POST':
        new_group = request.form.get(u'group_added')
        if new_group:
            data_dict = {
                u"id": new_group,
                u"object": id,
                u"object_type": u'package',
                u"capacity": u'public'
            }
            try:
                toolkit.get_action(u'member_create')(context, data_dict)
            except NotFound:
                return base.abort(404, _(u'Group not found'))
        removed_group = None
        for param in request.form:
            if param.startswith(u'group_remove'):
                removed_group = param.split(u'.')[-1]
                break
        if removed_group:
            data_dict = {
                u"id": removed_group,
                u"object": id,
                u"object_type": u'package'
            }

            try:
                toolkit.get_action(u'member_delete')(context, data_dict)
            except NotFound:
                return base.abort(404, _(u'Group not found'))
        return helpers.redirect_to(u'user_groups.user_groups', id=id)

    try:
        users_groups = toolkit.get_action(
            'group_list')(context, {'all_fields': True, 'type': 'user group'})
        groups_by_id = dict()

        for group in users_groups:
            user_groups = toolkit.get_action(
                u'group_list_authz')(context, {u'id': id})
            user_groups_ids = set(
                group[u'id'] for group in user_groups
            )
            group[u'user_member'] = (group[u'id'] in user_groups_ids)
            groups_by_id[group.get('id')] = group

        pkg_group_ids = set(
            group[u'id'] for group in pkg_dict.get(u'groups', [])
        )
        user_groups_ids = set([group['id'] for group in users_groups])

        pkg_dict['groups'] = [groups_by_id[group.get('id')] for group in pkg_dict['groups']
                              if group['id'] in user_groups_ids]
        groups_without_the_dataset = [[group[u'id'], group[u'display_name']]
                                      for group in users_groups
                                      if group[u'id'] not in pkg_group_ids]
        return toolkit.render('user_group/user_groups.html',
                              extra_vars={'pkg_dict': pkg_dict, 'group_dropdown': groups_without_the_dataset})
    except toolkit.ObjectNotFound:
        toolkit.abort(404, _('Dataset not found'))
