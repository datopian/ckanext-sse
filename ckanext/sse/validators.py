# encoding: utf-8
from __future__ import annotations

import logging
import json
import six
import ckan.plugins.toolkit as tk
import jsonschema

import re
from typing import Any

from ckanext.scheming.validation import scheming_validator
import ckan.lib.navl.dictization_functions as df
from ckan.model import (MAX_TAG_LENGTH, MIN_TAG_LENGTH)

from ckan.common import _
from ckan.types import (
    FlattenDataDict, FlattenKey, Context, FlattenErrorDict)

Invalid = df.Invalid
StopOnError = df.StopOnError
Missing = df.Missing
missing = df.missing

Invalid = tk.Invalid
_ = tk._

log = logging.getLogger(__name__)

@scheming_validator
def member_string_convert(arg1, arg2) -> Any:
    def validator(key: FlattenKey, data: FlattenDataDict,
                       errors: FlattenErrorDict, context: Context):
        '''Takes a list of members that is a comma-separated string (in data[key])
        and parses members names. They are also validated.'''
        if isinstance(data[key], str):
            members = [member.strip() \
                    for member in data[key].split(',') \
                    if member.strip()]
        else:
            members = data[key]

        for member in members:
            member_length_validator(member)
            member_name_validator(member)

        data[key] = members

    return validator

def member_length_validator(value: Any) -> Any:
    """Ensures that tag length is in the acceptable range.
    """
    if len(value) < MIN_TAG_LENGTH:
        raise Invalid(
            _('Tag "%s" length is less than minimum %s') % (value, MIN_TAG_LENGTH)
        )
    if len(value) > MAX_TAG_LENGTH:
        raise Invalid(
            _('Tag "%s" length is more than maximum %i') % (value, MAX_TAG_LENGTH)
        )
    return value

def member_name_validator(value: Any) -> Any:
    """Ensures that tag does not contain wrong characters
    """
    tagname_match = re.compile(r'[\w \-.]*$', re.UNICODE)
    if not tagname_match.match(value):
        raise Invalid(_('Tag "%s" can only contain alphanumeric '
                        'characters, spaces (" "), hyphens ("-"), '
                        'underscores ("_") or dots (".")') % (value))
    return value

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
    try:
        if isinstance(value, six.string_types):
            _coverage_validator(json.loads(value))
        elif isinstance(value, dict):
            _coverage_validator(value)
        else:
            raise Invalid(
                _("Invalid JSON object. Please provide JSON in the correct format.")
            )
    except Exception:
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
            "type": "object",
            "properties": {
                "fields": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
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
                },
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
    if value not in ["regular", "documentation", "historic", "related_data", "related_reports_and_documents", "historical_reports_and_documents"]:
        raise Invalid(
            _('Resource type must be either "regular", "documentation", "historic", "related_data", "related_reports_and_documents" or "historical_reports_and_documents"')
        )
    return value


def ib1_trust_framework_validator(value, context):
    if not value:
        return
    trust_framework = [
        "http://open-energy.registry.ib1.org",
        "http://general.registry.ib1.org",
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
