from ckan.plugins import toolkit
import ckan.model as model
from logging import getLogger

log = getLogger(__name__)

def is_org_admin_by_package_id(pkg_name):
    if not pkg_name or toolkit.current_user.is_anonymous:
        return False
    
    if toolkit.current_user.sysadmin:
        return True

    org_id = toolkit.get_action('package_show')({'ignore_auth': True}, {
        'id': pkg_name}).get('organization').get('id')
    org_data = toolkit.get_action('organization_show')(
        {'ignore_auth': True}, {'id': org_id, 'include_users': True})
    org_users = org_data.get('users', [])
    for user in org_users:
        if (user.get('capacity') == 'admin' or user.get('sysadmin')) and user.get('id') == toolkit.current_user.id:
            return True

    return False

def is_admin_of_any_org():
    if toolkit.current_user.is_anonymous:
        return False

    if toolkit.c.userobj.sysadmin:
        return True
    
    user_obj = model.User.get(toolkit.c.user)
    if not user_obj:
        return False

    org_memberships = model.Session.query(model.Member).\
        outerjoin(model.Group, model.Member.group_id == model.Group.id). \
        filter(model.Member.table_name == 'user').\
        filter(model.Member.table_id == user_obj.id).\
        filter(model.Group.type == 'organization').\
        filter(model.Member.state == 'active').\
        filter(model.Member.capacity == 'admin').\
        all()

    return len(org_memberships) > 0
