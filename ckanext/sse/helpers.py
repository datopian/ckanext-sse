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
        'full_name': toolkit._('Enter your Full Name (optional)'),
        'organisation_name': toolkit._('Organisation Name (optional)'),
        'job_title': toolkit._('Job Title (optional)'),
        'email_address': toolkit._('Email Address'),
        'title': toolkit._('Title'),
        'label': toolkit._('Category'),
        'organisation_type': toolkit._('Organisation Type'),
        'submission_type': toolkit._('Are you providing an example of how you have used our data or sharing an idea for how the data could be used?'),
        'usage_example': toolkit._('Please tell us how you are using our data'),
        'usage_idea': toolkit._('Do you have any ideas on how this data could be used?'),
        'showcase_permission': toolkit._('Are you happy for us to link to your re-use on our showcases section?'),
        'showcase_permission_other': toolkit._('Other Permission Details'),
        'additional_information': toolkit._('Is there anything else you would like to inform us about with your submission?'),
        'contact_permission': toolkit._('Are you happy for us to contact you about this request or feedback?'),
        'submitted_at': toolkit._('Submitted'),
        'dataset': toolkit._('What Data Asset are you providing a Data Re-Use submission on? '),
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
