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
        if value is None:
            return value
        value_lower = value.lower() if isinstance(value, str) else value
        choices_lower = [choice.lower() if isinstance(choice, str) else choice for choice in choices]
        
        if value_lower not in choices_lower:
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
    reuse_type_choices = ['Example', 'Idea']  # Renamed from usage_type
    
    schema = {
        "full_name": [ignore_missing, unicode_safe],
        "email_address": [not_empty, email_validator],
        "organisation_name": [ignore_missing, unicode_safe],
        "organisation_type": [not_empty, choice_validator(organisation_type_choices)],
        "title": [not_empty, unicode_safe],
        "label": [not_empty, choice_validator(label_choices)],
        "package_id": [not_empty, unicode_safe, package_id_exists],
        "reuse_type": [not_empty, choice_validator(reuse_type_choices)],
        "description": [ignore_missing, unicode_safe], 
        "additional_information": [ignore_missing, unicode_safe],
        "contact_permission": [ignore_missing, boolean_validator],
        "visible_org_permission": [ignore_missing, boolean_validator],
        "present_in_user_engagement_meeting": [ignore_missing, boolean_validator],
        'image_url': [ignore_missing, unicode_safe],
        'image_upload': [ignore_missing],
        'image_display_url': [ignore_missing, unicode_safe],
        'dashboard_url': [ignore_missing, unicode_safe],
        "user_id": [ignore_missing, unicode_safe],
        "state": [ignore_missing, choice_validator(['pending', 'approved', 'rejected'])],
        "id": [ignore_missing, unicode_safe], 
    }
    return schema


@schema.validator_args
def data_reuse_patch_schema(not_empty, ignore_missing, unicode_safe):
    """Schema for patching data reuse submissions (approve/reject only)."""
    return {
        "id": [not_empty, unicode_safe],
        "state": [not_empty, choice_validator(['pending', 'approved', 'rejected'])],
        "feedback": [ignore_missing, unicode_safe],
    }
