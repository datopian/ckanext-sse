# Overrides from ckanext-activity
from ckan.authz import is_sysadmin
from ckan.plugins import toolkit as tk
from ckan.logic import validate
import ckan.model as model
from ckan.common import _
from ckanext.activity.logic import schema
from ckanext.activity.model import activity as core_model_activity
from datetime import timedelta


import datetime
import logging

log = logging.getLogger(__name__)


@validate(schema.default_dashboard_activity_list_schema)
@tk.side_effect_free
def dashboard_activity_list_for_all_users(
    context, data_dict
) -> list[dict[str]]:
    """Return all the users's dashboard activity
       stream.

    Unlike the activity dictionaries returned by other ``*_activity_list``
    actions, these activity dictionaries have an extra boolean value with key
    ``is_new`` that tells you whether the activity happened since the user last
    viewed her dashboard (``'is_new': True``) or not (``'is_new': False``).

    The user's own activities are always marked ``'is_new': False``.

    :param offset: where to start getting activity items from
        (optional, default: ``0``)
    :type offset: int
    :param limit: the maximum number of activities to return
        (optional, default: ``31`` unless set in site's configuration
        ``ckan.activity_list_limit``, upper limit: ``100`` unless set in
        site's configuration ``ckan.activity_list_limit_max``)
    :type limit: int

    :rtype: list of activity dictionaries

    """
    if not is_sysadmin(context['user']):
        return {
            'errors': {'auth': [_('User not authorized')]},
            'error_summary': {_('auth'): _('User not authorized')},
        }

    lists = list()
    today = datetime.date.today()
    yesterday = today - timedelta(days=1)
    user_list = tk.get_action('user_list')({"ignore_auth": True})
    for user in user_list:
        user_id = user.get('id')
        offset = data_dict.get("offset", 0)
        # defaulted, limited & made an int by schema
        limit = data_dict["limit"]
        before = data_dict.get("before")
        after = data_dict.get("after")
        # FIXME: Filter out activities whose subject or object the user is not
        # authorized to read.
        activity_objects = core_model_activity.dashboard_activity_list(
            user_id,
            limit=limit,
            offset=offset,
            before=before,
            after=after
        )

        activity_dicts = core_model_activity.activity_list_dictize(
            activity_objects, context
        )

        # Mark the new (not yet seen by user) activities.
        strptime = datetime.datetime.strptime
        fmt = "%Y-%m-%dT%H:%M:%S.%f"
        dashboard = model.Dashboard.get(user_id)
        last_viewed = None
        if dashboard:
            last_viewed = dashboard.activity_stream_last_viewed
        for activity in activity_dicts:
            if activity["user_id"] == user_id:
                # Never mark the user's own activities as new.
                activity["is_new"] = False
            elif last_viewed:
                activity["is_new"] = (
                    strptime(activity["timestamp"], fmt) > last_viewed
                )

        lists.append([{'username': user.get('fullname') or user.get('name') or user.get('id'),
                     'activities': [
            element for element in activity_dicts
            if datetime.datetime.strptime(element["timestamp"], "%Y-%m-%dT%H:%M:%S.%f").date() == yesterday == yesterday
        ]}])

    flat_list = list()

    for row in lists:
        flat_list += row

    return flat_list
