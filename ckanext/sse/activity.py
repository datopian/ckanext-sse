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
    """Return yesterday's activities grouped by the user that performed them.

    Queries the activity table once for all of yesterday's activities
    instead of iterating over every user, so the response stays fast
    regardless of how many users exist.

    Each returned item has the shape::

        {"username": <fullname or name>, "activities": [<activity dict>, ...]}

    Activity dictionaries include ``'is_new': False`` for compatibility with
    the ``dashboard_activity_list`` output format.

    :rtype: list of dictionaries
    """
    if not is_sysadmin(context['user']):
        return {
            'errors': {'auth': [_('User not authorized')]},
            'error_summary': {_('auth'): _('User not authorized')},
        }

    today = datetime.date.today()
    yesterday = today - timedelta(days=1)
    yesterday_start = datetime.datetime.combine(yesterday, datetime.time.min)
    today_start = datetime.datetime.combine(today, datetime.time.min)

    activity_objects = (
        model.Session.query(core_model_activity.Activity)
        .filter(core_model_activity.Activity.timestamp >= yesterday_start)
        .filter(core_model_activity.Activity.timestamp < today_start)
        .filter(core_model_activity.Activity.user_id.isnot(None))
        .order_by(core_model_activity.Activity.timestamp.asc())
        .all()
    )

    if not activity_objects:
        return []

    activity_dicts = core_model_activity.activity_list_dictize(
        activity_objects, context
    )

    user_ids = {a["user_id"] for a in activity_dicts if a.get("user_id")}
    users_by_id = {
        user.id: user
        for user in model.Session.query(model.User)
        .filter(model.User.id.in_(user_ids))
        .all()
    }

    activities_by_user = {}
    for activity in activity_dicts:
        user_id = activity.get("user_id")
        if user_id not in users_by_id:
            continue
        activity["is_new"] = False
        activities_by_user.setdefault(user_id, []).append(activity)

    return [
        {
            'username': users_by_id[user_id].fullname
            or users_by_id[user_id].name
            or user_id,
            'activities': activities,
        }
        for user_id, activities in activities_by_user.items()
    ]
