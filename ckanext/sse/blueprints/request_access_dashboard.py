from logging import getLogger
from flask import Blueprint, render_template, request, redirect, url_for, flash
from ckan.plugins import toolkit
from ckan import model
from ckanext.sse.logic import is_user_id_present_in_the_dict_list
from ckan.common import _
from ckanext.sse.helpers import is_org_admin_by_package_id, is_admin_of_any_org
from ckanext.sse import model as custom_model
from ckanext.sse.logic import mail_rejected_user
from ckanext.s3filestore.views.resource import resource_download

import os
access_requests_blueprint = Blueprint('access_requests', __name__)
ssen_blueprint = Blueprint('ssen', __name__)


log = getLogger(__name__)


@ssen_blueprint.route('/dataset/<id>/resource/<resource_id>/download/<filename>')
def custom_download(id, resource_id, filename):
    pkg = toolkit.get_action('package_show')({}, {'id': id})

    if pkg.get('is_restricted'):
        privileged_context = {'ignore_auth': True}
        user = model.User.get(toolkit.c.user)

        if not user:
            return redirect(f"{os.environ.get('CKAN_FRONTEND_SITE_URL')}/auth/error?error=You do not have access to this resource")    

        is_sysadmin = user.sysadmin
        is_email_on_the_allowed_domains = any(user.email.lower().endswith(
            "@" + domain.strip()) for domain in os.environ.get('CKANEXT__SSE__REQUEST_ACCESS_ALLOWED_EMAIL_DOMAINS', '').lower().strip().split(','))
        belong_to_the_dataset_org = is_user_id_present_in_the_dict_list(user.id, toolkit.get_action('organization_show')(privileged_context, {
            'id': pkg.get('organization').get('id')}).get('users'))
        is_already_allowed_to_see_the_dataset = is_user_id_present_in_the_dict_list(user.id, toolkit.get_action('package_collaborator_list')(
            privileged_context, {'id': pkg.get('id')}))

        if not is_sysadmin and not is_email_on_the_allowed_domains and not belong_to_the_dataset_org and not is_already_allowed_to_see_the_dataset:
            return redirect(f"{os.environ.get('CKAN_FRONTEND_SITE_URL')}/auth/error?error=You not have access to this resource")

    return resource_download(None, id, resource_id, filename)


@access_requests_blueprint.route('/access_requests')
def access_requests_dashboard():
    """
    Dashboard to display and manage access requests for admins.
    """
    user_id = toolkit.c.userobj.id if toolkit.c.userobj else None

    if not user_id:
        flash(_("You must be logged in to view access requests."),
              category='alert-danger')
        return redirect(url_for('user.login'))

    is_sysadmin = toolkit.c.userobj.sysadmin
    org_ids = []

    if not is_sysadmin:
        user_obj = model.User.get(toolkit.c.user)
        org_memberships = model.Session.query(model.Group).\
            outerjoin(model.Member, model.Member.group_id == model.Group.id). \
            filter(model.Member.table_name == 'user').\
            filter(model.Member.table_id == user_obj.id).\
            filter(model.Group.type == 'organization').\
            filter(model.Member.state == 'active').\
            filter(model.Member.capacity == 'admin').\
            all()
        for membership in org_memberships:
            org_ids.append(membership.id)

    if not is_sysadmin and not org_ids:
        flash(_("You do not have permission to view access requests."),
              category='alert-danger')

        return redirect(url_for('home.index'))

    requests = []
    if is_sysadmin:
        requests = custom_model.PackageAccessRequest.get_all()
    else:
        requests.extend(custom_model.PackageAccessRequest.get_by_orgs(
            org_ids))

    return render_template('access_requests/access_requests_dashboard.html',
                           requests=requests,
                           is_sysadmin=is_sysadmin,
                           org_ids=org_ids)


@access_requests_blueprint.route('/access_requests/update_status', methods=['POST'])
def update_request_status():
    """
    Endpoint to handle approving, revoking or rejecting access requests.
    """

    if toolkit.current_user.is_anonymous or not is_admin_of_any_org():
        toolkit.abort(403)

    request_id = request.form.get('request_id')
    action = request.form.get('action')
    rejection_message = request.form.get('rejection_message')

    if not request_id or not action:
        flash(_("Invalid request."), category='alert-danger')
        return redirect(url_for('access_requests.access_requests_dashboard'))

    request_obj = custom_model.PackageAccessRequest.get(request_id)

    if not request_obj:
        flash(_("Request not found."), category='alert-danger')
        return redirect(url_for('access_requests.access_requests_dashboard'))

    if not is_org_admin_by_package_id(request_obj.package_id):
        flash(_("You do not have access to this package."),
              category='alert-danger')
        return redirect(url_for('access_requests.access_requests_dashboard'))

    approved_or_rejected_by_user_id = toolkit.c.userobj.id

    if action == 'approve':
        new_status = 'approved'
        rejection_message = None
    elif action == 'reject':
        new_status = 'rejected'
    elif action == 'revoke':
        new_status = 'revoked'
    else:
        flash(_("Invalid action."), category='alert-danger')
        return redirect(url_for('access_requests.access_requests_dashboard'))

    custom_model.PackageAccessRequest.update_status(
        request_id, new_status, rejection_message, approved_or_rejected_by_user_id
    )

    pkg = toolkit.get_action('package_show')({'ignore_auth': True}, {
        'id': request_obj.package_id})
    user = toolkit.get_action('user_show')(
        {"user": os.environ.get('CKAN_SYSADMIN_NAME')}, {'id': request_obj.user_id})

    org_id = pkg.get('organization').get('id')

    package_link = f"{os.environ.get('CKAN_FRONTEND_SITE_URL')}/{pkg.get('organization').get('name')}/{pkg.get('name')}"
    site_title = os.environ.get('CKAN_FRONTEND_SITE_TITLE')
    site_url = os.environ.get('CKAN_FRONTEND_SITE_URL')

    email_notification_dict = {
        'user_id': request_obj.user_id,
        'site_url': site_url,
        'site_title': site_title,
        'package_link': package_link,
        'user_name': user.get('full_name') or user.get('display_name') or user.get('name'),
        'user_email': user.get('email'),
        'package_name': pkg.get('name') or pkg.get('id'),
        'package_title': pkg.get('title') or pkg.get('name') or pkg.get('id'),
        'package_id': pkg.get('id'),
        'org_id': org_id,
    }

    if action == 'approve':
        toolkit.get_action('package_collaborator_create')({'ignore_auth': True, 'send_approval_email': True}, {'id': pkg.get(
            'id'), 'user_id': user.get('id'), 'capacity': 'member'})
    else:
        if rejection_message:
            rejection_message = f'''Reason:
                {rejection_message}
            '''
        if action == 'revoke':
            toolkit.get_action('package_collaborator_delete')({'ignore_auth': True, 'send_reject_email': True, 'revoke_message': rejection_message}, {'id': pkg.get(
                'id'), 'user_id': user.get('id')})
        else:
            mail_rejected_user(email_notification_dict,
                            rejection_message, new_status)
    flash(
        _(f"Request {request_id} {new_status} successfully."), category='alert-success')
    return redirect(url_for('access_requests.access_requests_dashboard'))


def get_blueprints():
    return [access_requests_blueprint, ssen_blueprint]
