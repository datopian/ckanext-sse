
import json
import six
import ckan.plugins.toolkit as tk

Invalid = tk.Invalid
_ = tk._


def coverage_json_object(value, context):
    """
    Validates that the value is a valid coverage JSON object.
    """
    if not value:
        return
    elif isinstance(value, six.string_types):
        try:
            loaded = json.loads(value)

            if not isinstance(loaded, dict):
                raise  Invalid( _('Invalid JSON format. Please provide JSON in the correct format: eg. {'
                              '"name": "", "type": "spatial or temporal", "location_name": "", '
                              '"location_geojson": {} }}')
                            )
            return value
        except (ValueError, TypeError) as e:
            raise  Invalid( _('Invalid JSON format. Please provide JSON in the correct format: eg. {'
                              '"name": "", "type": "spatial or temporal", "location_name": "", '
                              '"location_geojson": {} }}')
                            )

    elif isinstance(value, dict):
        try:
            return json.dumps(value)
        except (ValueError, TypeError) as e:
            raise Invalid(_('Invalid JSON object: {}').format(e))
    else:
        raise Invalid(
            _('Unsupported type for JSON field: {}').format(type(value)))