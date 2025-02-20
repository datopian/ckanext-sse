import ckan.logic.schema as schema
import ckan.lib.navl.dictization_functions as df

import logging

log = logging.getLogger(__name__)


@schema.validator_args
def package_request_access_schema(not_empty):
    schema = {
        "package_id": [not_empty],
        "message": [not_empty],
        "user_organization": [],
    }
    return schema