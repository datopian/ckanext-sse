"""
Authorization functions for form submissions and usage ideas.
"""
from logging import getLogger

import ckan.plugins.toolkit as tk
from .model import FormResponse

log = getLogger(__name__)


def data_reuse_create(context, data_dict):
    """
    Authorization for creating data reuse submissions (examples or ideas).

    Any authenticated user may submit data reuse examples and ideas.
    Anonymous users are not allowed.
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

    # Get the submission to check ownership. Look it up in any state - a
    # submitter's own submission is usually still pending.
    submission_id = data_dict.get('id')
    user_obj = context.get('auth_user_obj')
    if submission_id and user_obj:
        try:
            submission = FormResponse.get(submission_id, include_all=True)
            if submission and submission.user_id == user_obj.id:
                return {'success': True}
        except Exception:
            log.exception(
                'Could not check ownership of data reuse submission %s',
                submission_id,
            )

    # Anyone else is denied; sysadmins bypass this check.
    return {'success': False}


@tk.auth_allow_anonymous_access
def data_reuse_list(context, data_dict):
    """
    Authorization for listing data reuse submissions.

    Anyone may list approved submissions; the action redacts submitter
    details for non-sysadmins. Listing submissions in any other state
    (include_all) stays sysadmin-only.
    """
    if tk.asbool(data_dict.get('include_all', False)):
        return {'success': False}

    return {'success': True}


@tk.auth_allow_anonymous_access
def data_reuse_show(context, data_dict):
    """
    Authorization for showing a specific data reuse submission.

    Anyone may view an approved submission; the action redacts submitter
    details for non-sysadmins. Viewing a submission in any other state
    (include_all) stays sysadmin-only.
    """
    if tk.asbool(data_dict.get('include_all', False)):
        return {'success': False}

    return {'success': True}

def data_reuse_delete(context, data_dict):
    """
    Authorization for deleting data reuse submissions.
    
    Only sysadmins can delete submissions.
    """
    return {'success': False}


@tk.chained_auth_function
def datastore_search_sql(next_auth, context, data_dict):
    """
    Restrict ``datastore_search_sql`` to authenticated users.

    Chained because ``ckanext.datastore`` already registers this name and
    ``ckan/authz.py`` raises if two plugins claim one non-chained.

    Omitting ``@tk.auth_allow_anonymous_access`` is not enough on its own:
    ``is_authorized`` gates on ``auth_user_obj`` being absent, but the action
    API sets it to flask-login's ``AnonymousUser`` (``ckan/views/api.py``),
    which is truthy. Hence the explicit check, which reads ``is_anonymous``
    rather than truthiness. ``user`` is still honoured so internal calls that
    pass only a name keep working.
    """
    user_obj = context.get('auth_user_obj')
    anonymous = user_obj is None or getattr(user_obj, 'is_anonymous', False)

    if anonymous and not context.get('user'):
        return {
            'success': False,
            'msg': tk._(
                'datastore_search_sql is available to authenticated users only'
            ),
        }

    return next_auth(context, data_dict)
