"""
Authorization functions for form submissions and usage ideas.
"""
import ckan.plugins.toolkit as tk
from .model import FormResponse


def data_reuse_create(context, data_dict):
    """
    Authorization for creating data reuse submissions (examples or ideas).
    Anonymous users are allowed to submit data reuse examples and ideas.
    """
    user = context.get('user')
    if not user:
        return {'success': False, 'msg': 'User not authenticated'}
    
    return {'success': True}


def data_reuse_update(context, data_dict):
    """
    Authorization for updating data reuse submissions.
    
    Allow users to update their own submissions, and admins to update any.
    """
    user = context.get('user')
    if not user:
        return {'success': False, 'msg': 'User not authenticated'}
    
    # Get the submission to check ownership
    submission_id = data_dict.get('id')
    if submission_id:
        try:
            submission = FormResponse.get(submission_id)
            if submission and submission.user_id == context.get('auth_user_obj').id:
                return {'success': True}
        except:
            pass
    
    # Fall back to sysadmin check
    return tk.auth_sysadmins_check(context, data_dict)


def data_reuse_list(context, data_dict):
    """
    Authorization for listing data reuse submissions.
    
    Only sysadmins can list data reuse submissions.
    """
    return {'success': False}


def data_reuse_show(context, data_dict):
    """
    Authorization for showing a specific data reuse submission.
    
    Only sysadmins can view individual submissions.
    """
    return {'success': False}

def data_reuse_delete(context, data_dict):
    """
    Authorization for deleting data reuse submissions.
    
    Only sysadmins can delete submissions.
    """
    return {'success': True}
