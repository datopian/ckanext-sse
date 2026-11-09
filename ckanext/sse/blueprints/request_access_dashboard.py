from datetime import datetime
from logging import getLogger
from flask import Blueprint, render_template, request, redirect, url_for, flash
from ckan.plugins import toolkit
from ckan import model
from ckanext.sse.logic import is_user_id_present_in_the_dict_list
from ckan.common import _
from ckanext.sse.helpers import is_org_admin_by_package_id, is_admin_of_any_org
from ckanext.sse import model as custom_model
from ckanext.sse.logic import mail_rejected_user
from ckanext.sse.audit import emit_access_request
from ckanext.s3filestore.views.resource import resource_download
from ckan.lib.pagination import Page

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


PAGE_SIZE = 25


def _admin_org_ids(user_obj):
    """Organisations the user administers; None for a sysadmin (all of them)."""
    if user_obj.sysadmin:
        return None
    memberships = model.Session.query(model.Group.id).\
        join(model.Member, model.Member.group_id == model.Group.id).\
        filter(model.Member.table_name == 'user').\
        filter(model.Member.table_id == user_obj.id).\
        filter(model.Group.type == 'organization').\
        filter(model.Member.state == 'active').\
        filter(model.Member.capacity == 'admin').\
        all()
    return [m.id for m in memberships]


def _date_arg(name):
    try:
        return datetime.strptime(request.args.get(name, ''), '%Y-%m-%d').date()
    except ValueError:
        return None


@access_requests_blueprint.route('/access_requests')
def access_requests_dashboard():
    """
    Dashboard to display and manage access requests for admins.

    Filters come from the query string, so a filtered view can be linked to:
    status (default pending, "all" for every status), q (requester), dataset,
    org, from/to (requested date, YYYY-MM-DD), sort (activity or requested)
    and page.
    """
    user_obj = toolkit.c.userobj
    if not user_obj:
        flash(_("You must be logged in to view access requests."),
              category='alert-danger')
        return redirect(url_for('user.login'))

    org_ids = _admin_org_ids(user_obj)
    if org_ids is not None and not org_ids:
        flash(_("You do not have permission to view access requests."),
              category='alert-danger')
        return redirect(url_for('home.index'))

    filters = {
        'status': request.args.get('status') or 'pending',
        'q': (request.args.get('q') or '').strip(),
        'dataset': request.args.get('dataset') or '',
        'org': request.args.get('org') or '',
        'from': request.args.get('from') or '',
        'to': request.args.get('to') or '',
        'sort': 'requested' if request.args.get('sort') == 'requested' else 'activity',
    }
    try:
        page_number = max(int(request.args.get('page', 1)), 1)
    except ValueError:
        page_number = 1

    items, total, status_counts = custom_model.PackageAccessRequest.search(
        org_ids=org_ids,
        status=filters['status'],
        q=filters['q'] or None,
        package_id=filters['dataset'] or None,
        org_id=filters['org'] or None,
        requested_from=_date_arg('from'),
        requested_to=_date_arg('to'),
        sort=filters['sort'],
        offset=(page_number - 1) * PAGE_SIZE,
        limit=PAGE_SIZE,
    )
    datasets, orgs = custom_model.PackageAccessRequest.filter_options(org_ids)

    def page_url(**changes):
        params = {k: v for k, v in filters.items() if v}
        params.update(changes)
        return url_for('access_requests.access_requests_dashboard',
                       **{k: v for k, v in params.items() if v})

    page = Page(
        collection=items, page=page_number, items_per_page=PAGE_SIZE,
        item_count=total, presliced_list=True,
        url=lambda page=None, **kw: page_url(page=page),
    )

    return render_template('access_requests/access_requests_dashboard.html',
                           page=page,
                           requests=items,
                           total=total,
                           status_counts=status_counts,
                           filters=filters,
                           datasets=datasets,
                           orgs=orgs,
                           page_url=page_url,
                           is_sysadmin=user_obj.sysadmin)


@access_requests_blueprint.route('/access_requests/<request_id>/history')
def access_request_history(request_id):
    """The history modal's content: the request and every step taken on it."""
    user_obj = toolkit.c.userobj
    if not user_obj:
        toolkit.abort(403)
    request_obj = custom_model.PackageAccessRequest.get(request_id)
    if not request_obj:
        toolkit.abort(404)
    org_ids = _admin_org_ids(user_obj)
    if org_ids is not None and request_obj.org_id not in org_ids:
        toolkit.abort(403)
    return render_template('access_requests/snippets/history_modal.html',
                           item=request_obj)


def _back_to_dashboard():
    """The dashboard view the decision was made from (filters, page), if safe."""
    target = request.form.get('return_to') or ''
    if target.startswith('/access_requests') and '//' not in target and '\\' not in target:
        return target
    return url_for('access_requests.access_requests_dashboard')


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
        return redirect(_back_to_dashboard())

    request_obj = custom_model.PackageAccessRequest.get(request_id)

    if not request_obj:
        flash(_("Request not found."), category='alert-danger')
        return redirect(_back_to_dashboard())

    if not is_org_admin_by_package_id(request_obj.package_id):
        emit_access_request(
            action or "unknown", "failure", request_id=request_id,
            package_id=request_obj.package_id,
            requester_id=request_obj.user_id, reason="not an admin of the dataset's organisation",
        )
        flash(_("You do not have access to this package."),
              category='alert-danger')
        return redirect(_back_to_dashboard())

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
        return redirect(_back_to_dashboard())

    custom_model.PackageAccessRequest.update_status(
        request_id, new_status, rejection_message, approved_or_rejected_by_user_id
    )
    emit_access_request(
        new_status, "success", request_id=request_id,
        package_id=request_obj.package_id, requester_id=request_obj.user_id,
        reason=rejection_message,
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
    return redirect(_back_to_dashboard())


def get_blueprints():
    return [access_requests_blueprint, ssen_blueprint]
