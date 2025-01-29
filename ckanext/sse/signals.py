import datetime
import logging
import json
import ckan.plugins.toolkit as tk
import ckan.lib.search as search
from sqlalchemy.sql.expression import func
from sqlalchemy.sql.functions import coalesce
from sqlalchemy.dialects.postgresql import TEXT, JSONB

log = logging.getLogger(__name__)

def get_subscriptions():
    return {
        tk.signals.action_succeeded: [
            {"sender": "datastore_upsert", "receiver": on_datastore_updated},
            {"sender": "datastore_delete", "receiver": on_datastore_updated},
            {"sender": "datastore_create", "receiver": on_datastore_updated},
        ]
    }


def on_datastore_updated(sender, **kwargs):
    context = kwargs.get("context")
    data_dict = kwargs.get("data_dict")
    model = context['model']
    resource = model.Resource.get(data_dict['resource_id'])
    assert resource
    flag = datetime.datetime.utcnow().isoformat()

    model.Session.query(model.Resource).filter(
        model.Resource.id == data_dict['resource_id']
    ).update(
        {
            'extras': func.jsonb_set(
                coalesce(
                    model.resource_table.c.extras,
                    '{}',
                ).cast(JSONB),
                '{last_datastore_modified}',
                json.dumps(flag),
            ).cast(TEXT)
        },
        synchronize_session='fetch',
    )
    model.Session.commit()
    model.Session.expire(resource, ['extras'])

    context = {
        'model': model,
        'ignore_auth': True,
        'validate': False,
        'use_cache': False
    }

    psi = search.PackageSearchIndex()
    _data_dict = tk.get_action('package_show')(context, {
        'id': resource.package_id
    })
    for resource in _data_dict['resources']:
        if resource['id'] == data_dict['resource_id']:
            resource['last_datastore_modified'] = flag
            psi.index_package(_data_dict)
            break

