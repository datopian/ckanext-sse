import ckan.plugins as p
from ckan.plugins import toolkit as tk
from ckan.logic.auth.get import package_show as package_show_check_access
from ckan.authz import auth_is_anon_user

def custom_package_show(context, data_dict):
    """
    Allows members of user groups to access the datasets that belong to them.
    """

    if auth_is_anon_user(context) or not data_dict.get('groups') or context['auth_user_obj'].sysadmin:
        return package_show_check_access(context, data_dict)
    
    users_groups_ids = set([group['id'] for group in tk.get_action('group_list_authz')(context) if group['type'] == 'user group'])
    if len(users_groups_ids):
        for group in data_dict.get('groups'):
            if group['id'] in users_groups_ids:
                return {"success": True}

    return package_show_check_access(context, data_dict)
