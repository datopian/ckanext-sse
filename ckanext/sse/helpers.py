from ckan.plugins import toolkit
import ckan.model as model
from logging import getLogger

log = getLogger(__name__)

def get_data_reuse_field_labels():
    """
    Returns a dictionary mapping field names to their corresponding labels/questions
    for the data reuse form. This allows dynamic label management.
    """
    return {
        'full_name': toolkit._('Full Name'),
        'email_address': toolkit._('Email Address'),
        'job_title': toolkit._('Job Title'),
        'organisation_name': toolkit._('Organisation Name '),
        'organisation_type': toolkit._('Organisation Type'),
        'title': toolkit._('Title '),
        
        'dataset': toolkit._('Data Asset used?'),
        'label': toolkit._('Label '),
        'description': toolkit._('Description'),
        'showcase_permission': toolkit._('Permission to showcase'),
        'showcase_permission_other': toolkit._('Other Permission Details'),
        'additional_information': toolkit._('Additional Information'),
        'contact_permission': toolkit._('Permission to contact'),
        'submitted_at': toolkit._('Submitted'),
    }

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
