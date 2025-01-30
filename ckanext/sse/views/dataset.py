from ckan.views.dataset import GroupView as BaseGroupView
from flask import Blueprint
from ckan.plugins import toolkit as tk
import ckan.lib.base as base
from ckan.common import _, config, g, request
import ckan.logic as logic
from ckan.lib.helpers import helper_functions as h

NotFound = logic.NotFound

blueprint = Blueprint(
    u'ssen_dataset',
    __name__,
    url_prefix=u'/dataset',
    url_defaults={u'package_type': u'dataset'}
)

def groupViewByTypeFactory(group_type):
    class GroupView(BaseGroupView):
        def __init__(self):
            super()

        def _prepare(self, id):
            context, pkg_dict = super()._prepare(id)
            group_type_key = group_type + "s"
            pkg_dict["groups"] = pkg_dict[group_type_key] if group_type_key in pkg_dict else []
            return context, pkg_dict

        def get(self, package_type: str, id: str) -> str:
            context, pkg_dict = self._prepare(id)
            dataset_type = pkg_dict[u'type'] or package_type
            context[u'is_member'] = True
            users_groups = tk.get_action(u'group_list_authz')(context, {u'id': id})

            ### This line below is the only override from core
            users_groups = list(filter(lambda x: x.get("type") == group_type, users_groups))
            ###

            pkg_group_ids = set(
                group[u'id'] for group in pkg_dict.get(u'groups', [])
            )

            user_group_ids = set(group[u'id'] for group in users_groups)

            group_dropdown = [[group[u'id'], group[u'display_name']]
                              for group in users_groups
                              if group[u'id'] not in pkg_group_ids]

            for group in pkg_dict.get(u'groups', []):
                group[u'user_member'] = (group[u'id'] in user_group_ids)

            g.pkg_dict = pkg_dict
            g.group_dropdown = group_dropdown

            return base.render(
                u'package/group_list.html', {
                    u'dataset_type': dataset_type,
                    u'pkg_dict': pkg_dict,
                    u'group_dropdown': group_dropdown
                }
            )

        def post(self, package_type: str, id: str):
            context = self._prepare(id)[0]
            new_group = request.form.get(u'group_added')
            if new_group:
                data_dict = {
                    u"id": new_group,
                    u"object": id,
                    u"object_type": u'package',
                    u"capacity": u'public'
                }
                try:
                    tk.get_action(u'member_create')(context, data_dict)
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
                    tk.get_action(u'member_delete')(context, data_dict)
                except NotFound:
                    return base.abort(404, _(u'Group not found'))
            return h.redirect_to(u'{}.{}'.format("ssen_dataset", group_type + "s"), id=id)
    return GroupView 

UserGroupView = groupViewByTypeFactory("user_group")
DefaultGroupView = groupViewByTypeFactory("group")

blueprint.add_url_rule(
    u'/user_groups/<id>', view_func=UserGroupView.as_view(str(u'user_groups'))
)

blueprint.add_url_rule(
    u'/groups/<id>', view_func=DefaultGroupView.as_view(str(u'groups'))
)

