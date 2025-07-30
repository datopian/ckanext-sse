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


def choice_validator(choices):
    """Custom validator for choice fields"""
    def validator(value, context):
        if value not in choices:
            raise df.Invalid(f'Value must be one of: {", ".join(choices)}')
        return value
    return validator


@schema.validator_args 
def data_reuse_schema(not_empty, ignore_missing, unicode_safe, email_validator, boolean_validator, package_id_exists):
    """Schema for data reuse submissions - covers both usage examples and ideas"""
    
    label_choices = ['Community Support', 'Research Innovation', 'Sustainability']
    organisation_type_choices = [
        'Academic', 'Construction', 'Data Science', 'Energy Consultant',
        'Energy Utility', 'Government', 'Innovator', 'Local Authority', 
        'Regulator', 'Technology', 'Other'
    ]
    submission_type_choices = ['Example', 'Idea']  # Renamed from usage_type
    showcase_permission_choices = ['Yes', 'No', 'Others']
    
    schema = {
        "email_address": [not_empty, email_validator],
        "title": [not_empty, unicode_safe],
        "label": [not_empty, choice_validator(label_choices)],
        "organisation_type": [not_empty, choice_validator(organisation_type_choices)],
        "package_id": [not_empty, unicode_safe, package_id_exists],
        "submission_type": [not_empty, choice_validator(submission_type_choices)],
        "showcase_permission": [not_empty, choice_validator(showcase_permission_choices)],
        "job_title": [ignore_missing, unicode_safe],
        "full_name": [ignore_missing, unicode_safe],
        "organisation_name": [ignore_missing, unicode_safe],
        "usage_example": [ignore_missing, unicode_safe], 
        "usage_idea": [ignore_missing, unicode_safe], 
        "showcase_permission_other": [ignore_missing, unicode_safe],
        "additional_information": [ignore_missing, unicode_safe],
        "contact_permission": [ignore_missing, boolean_validator],
        "user_id": [ignore_missing, unicode_safe],
        "id": [ignore_missing, unicode_safe], 
    }
    return schema