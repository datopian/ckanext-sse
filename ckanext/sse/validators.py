
import json
import six
import ckan.plugins.toolkit as tk
import jsonschema

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
    

def schema_json_object(value, context):
    """
    Validates that the value is a valid frictionless schema JSON object.
    """
    if not value:
        return 
            
    def _schema_validator(value):
        frictionless_schema = {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "comment": {"type": "string"},
                    "description": {"type": "string"},
                    "title": {"type": "string"},
                    "type": {"type": "string"},
                    "example": {"type": "string"},
                    "unit": {"type": "string"}
                },
                "required": ["title", "type"],
                "additionalProperties": False
            }
        }

        try: 
            jsonschema.validate(value, frictionless_schema)
        except jsonschema.exceptions.ValidationError as e:
            raise Invalid(_(f"JSON schema is not valid according to Frictionless schema standard. {e.message}"))
        
    if isinstance(value, six.string_types):
        _schema_validator(json.loads(value))
    elif isinstance(value, dict):
        _schema_validator(value)
    else:
        raise Invalid(_("JSON schema is not valid according to Frictionless schema standard."))

    return value
        
def schema_output_string_json(value, context):

    if isinstance(value, six.string_types):
        try:
            return json.loads(value)
        except ValueError:
            return value
    return value


def resource_type(value, context):

    if value not in ['regular', 'documentation']:
        raise Invalid(_('Resource type must be either "regular" or "documentation"'))
    return value