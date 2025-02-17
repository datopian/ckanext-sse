import json
from sqlalchemy.sql.expression import func
from sqlalchemy.sql.functions import coalesce
from sqlalchemy.dialects.postgresql import TEXT, JSONB
import ckan.model as model
import ckan.lib.search as search
import ckan.plugins.toolkit as tk


def update_resource_extra(resource_id, field, value):
    resource = model.Resource.get(resource_id)
    assert resource
    model.Session.query(model.Resource).filter(
        model.Resource.id == resource_id
    ).update(
        {
            'extras': func.jsonb_set(
                coalesce(
                    model.resource_table.c.extras,
                    '{}',
                ).cast(JSONB),
                '{' + field + '}',
                json.dumps(value),
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
        if resource['id'] == resource_id:
            resource[field] = value
            psi.index_package(_data_dict)
            break
