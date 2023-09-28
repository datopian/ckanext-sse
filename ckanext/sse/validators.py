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

    def _coverage_validator(value):
        coverage_schema = {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "type": {"type": "string", "enum": ["spatial", "temporal"]},
                    "start": {"type": "string"},
                    "end": {"type": "string"},
                    "location_name": {"type": "string"},
                    "location_geojson": {"type": "object"},
                },
                "required": ["name", "type"],
                "additionalProperties": False,
            },
        }

        try:
            jsonschema.validate(value, coverage_schema)
        except jsonschema.exceptions.ValidationError as e:
            raise Invalid(
                _(
                    f"Invalid JSON object. Please provide JSON in the correct format. {e.message}"
                )
            )

    if isinstance(value, six.string_types):
        _coverage_validator(json.loads(value))
    elif isinstance(value, dict):
        _coverage_validator(value)
    else:
        raise Invalid(
            _("Invalid JSON object. Please provide JSON in the correct format.")
        )

    return value


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
                    "unit": {"type": "string"},
                },
                "required": ["title", "type"],
                "additionalProperties": False,
            },
        }

        try:
            jsonschema.validate(value, frictionless_schema)
        except jsonschema.exceptions.ValidationError as e:
            raise Invalid(
                _(
                    f"JSON schema is not valid according to Frictionless schema standard. {e.message}"
                )
            )

    if isinstance(value, six.string_types):
        _schema_validator(json.loads(value))
    elif isinstance(value, dict):
        _schema_validator(value)
    else:
        raise Invalid(
            _("JSON schema is not valid according to Frictionless schema standard.")
        )

    return value


def schema_output_string_json(value, context):
    if isinstance(value, six.string_types):
        try:
            return json.loads(value)
        except ValueError:
            return value
    return value


def resource_type_validator(value, context):
    if value not in ["regular", "documentation"]:
        raise Invalid(_(' Resource type must be either "regular" or "documentation"'))
    return value


def ib1_trust_framework_validator(value, context):
    if not value:
        return
    trust_framework = [
        "ib1:general.registry.ib1.org",
        "ib1:open-energy.registry.ib1.org",
    ]

    if value.lower() not in trust_framework:
        raise Invalid(
            _(
                "'ib1_trust_framework' must be one of {}".format(
                    ", ".join(trust_framework)
                )
            )
        )
    return value


def ib1_sensitivity_class_validator(value, context):
    if not value:
        return

    sensitivity_class = ["IB1-O", "IB1-SA", "IB1-SB"]

    if value not in sensitivity_class:
        raise Invalid(
            _(
                "'ib1_sensitivity_class' must be one of {}".format(
                    ", ".join(sensitivity_class)
                )
            )
        )

    return value


def ib1_dataset_assurance_validator(value, context):
    if not value:
        return

    dataset_assurance = [
        "IcebreakerOne.DatasetLevel1",
        "IcebreakerOne.DatasetLevel2",
        "IcebreakerOne.DatasetLevel3",
        "IcebreakerOne.DatasetLevel4",
    ]

    if value not in dataset_assurance:
        raise Invalid(
            _(
                "'ib1_dataset_assurance' must be one of {}".format(
                    ", ".join(dataset_assurance)
                )
            )
        )

    return value
