from datetime import datetime, date
from collections import OrderedDict

from sqlalchemy import orm, Column, String, Text, DateTime, ForeignKey, Enum
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import Unicode
from sqlalchemy.orm import relationship
from ckan.model.meta import metadata, Session
from ckan.model.types import make_uuid
from sqlalchemy.ext.declarative import declarative_base
import ckan.plugins.toolkit as tk

from ckan.model.package import Package
from ckan.model.group import Group
from ckan.model.user import User
import ckan.model.domain_object as DomainObject

Base = declarative_base(metadata=metadata)


class PackageAccessRequest(Base):
    """
    Custom table for your plugin to manage Package access requests.
    """
    __tablename__ = 'package_access_request'

    id = Column(String(60), primary_key=True, default=make_uuid)
    message = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.now)
    status = Column(Enum('pending', 'approved', 'rejected', 'revoked',
                    name="request_status_enum"), default='pending', nullable=False)
    rejection_message = Column(Text)
    approved_or_rejected_by_user_id = Column(String(60), ForeignKey('user.id'))

    package_id = Column(String(60), ForeignKey('package.id'), nullable=False)
    org_id = Column(String(60), ForeignKey('group.id'), nullable=False)
    user_id = Column(String(60), ForeignKey('user.id'), nullable=False)

    package = relationship(Package, foreign_keys=[package_id])
    organization = relationship(Group, foreign_keys=[org_id])
    user = relationship(User, foreign_keys=[user_id])
    approved_or_rejected_by_user = relationship(
        User, foreign_keys=[approved_or_rejected_by_user_id])

    def __repr__(self):
        return f"<PackageAccessRequest {self.id}>"

    @classmethod
    def create(cls, package_id, user_id, org_id, message):
        """
        Create a new access request.

        :param package_id: ID of the package.
        :param user_id: ID of the user making the request.
        :param org_id: ID of the organization related to the request.
        :param message: Message accompanying the request.
        :return: The created PackageAccessRequest object.
        """
        request = cls(
            package_id=package_id,
            user_id=user_id,
            org_id=org_id,
            message=message,
            status='pending'
        )
        Session.add(request)
        Session.commit()
        return request

    @classmethod
    def get(cls, request_id):
        """Get a PackageAccessRequest by ID"""
        return Session.query(cls).get(request_id)

    @classmethod
    def get_all(cls):
        """Get all the PackageAccessRequest"""
        return Session.query(cls).all()

    @classmethod
    def get_by_package(cls, package_id):
        """Get all PackageAccessRequests for a package"""
        return Session.query(cls).filter_by(package_id=package_id).all()

    @classmethod
    def get_by_package_user_and_status(cls, package_id, user_id, status):
        """Get all PackageAccessRequests for a package, status and user"""
        return Session.query(cls).filter_by(package_id=package_id, user_id=user_id, status=status).all()

    @classmethod
    def get_by_user(cls, user_id):
        """Get all PackageAccessRequests from a user"""
        return Session.query(cls).filter_by(user_id=user_id).all()

    @classmethod
    def get_by_org(cls, org_id):
        """Get all PackageAccessRequests from a user"""
        return Session.query(cls).filter_by(org_id=org_id).all()

    @classmethod
    def get_by_orgs(cls, org_ids):
        """Get all PackageAccessRequests from a user"""
        return Session.query(cls).filter_by(PackageAccessRequest.org_id.in_(org_ids)).all()

    @classmethod
    def delete(cls, request_id):
        """Delete a PackageAccessRequest by ID"""
        request = cls.get(request_id)
        if request:
            Session.delete(request)
            Session.commit()
            return True
        return False

    @classmethod
    def update_message(cls, request_id, new_message):
        """Update a PackageAccessRequest's message"""
        request = cls.get(request_id)
        if request:
            request.message = new_message
            Session.commit()
            return request
        return None

    @classmethod
    def update_status(cls, request_id, new_status, rejection_message=None, approved_or_rejected_by_user_id=None):
        """Update a PackageAccessRequest's status and optionally rejection message and approved_or_rejected_by_user_id"""
        request = cls.get(request_id)
        if request:
            request.status = new_status
            request.rejection_message = rejection_message
            request.approved_or_rejected_by_user_id = approved_or_rejected_by_user_id
            Session.commit()
            return request
        return None


class FormResponse(DomainObject.DomainObject, tk.BaseModel):

    """
    Generic model for storing dynamic form submissions using JSONB.
    This can handle usage ideas, usage example feedback forms, or any other dynamic forms response.
    """

    __tablename__ = "form_response"

    id = Column(Unicode(64), primary_key=True, default=make_uuid)
    type = Column(String(100), nullable=False)  # e.g., 'usage_idea', 'feedback', etc.
    submitted_at = Column(DateTime, default=datetime.utcnow)
    data = Column(JSONB, nullable=False)
    user_id = Column(
        String(60), ForeignKey("user.id"), nullable=True
    )  # Optional for anonymous submissions - NULLABLE
    package_id = Column(
        String(60), ForeignKey("package.id"), nullable=True
    )  # Optional reference to dataset - NULLABLE

    # Relationships
    user = relationship(User, foreign_keys=[user_id])
    package = relationship(Package, foreign_keys=[package_id])

    def as_dict(self):
        _dict = OrderedDict()
        table = orm.class_mapper(self.__class__).mapped_table
        for col in table.c:
            val = getattr(self, col.name)
            if isinstance(val, date):
                val = str(val)
            if isinstance(val, datetime):
                val = val.isoformat()
            _dict[col.name] = val
        return _dict
        
    @classmethod
    def create(cls, form_type, form_data, user_id=None, package_id=None):
        """
        Generic create method for any form type.

        :param form_type: Type of form (e.g., 'usage_idea', 'feedback', 'contact')
        :param form_data: Dictionary containing the form data
        :param user_id: Optional user ID
        :param package_id: Optional package/dataset ID
        :return: The created FormResponse object
        """
        submission = cls(
            type=form_type, data=form_data, user_id=user_id, package_id=package_id
        )
        Session.add(submission)
        Session.commit()
        return submission

    @classmethod
    def get(cls, id):
        """Get a FormResponse by ID"""
        return Session.query(cls).get(id)

    @classmethod
    def get_all(cls):
        """Get all FormResponses"""
        return Session.query(cls).all()

    @classmethod
    def get_by_form_type(cls, form_type):
        """Get all submissions by form type"""
        return Session.query(cls).filter_by(type=form_type).all()

    @classmethod
    def get_by_user(cls, user_id):
        """Get all submissions from a specific user"""
        return Session.query(cls).filter_by(user_id=user_id).all()

    @classmethod
    def get_by_package(cls, package_id):
        """Get all submissions related to a specific package/dataset"""
        return Session.query(cls).filter_by(package_id=package_id).all()

    @classmethod
    def get_by_data_field(cls, form_type, field_name, field_value):
        """
        Query submissions by a specific field in the JSONB data.

        Example: get_by_data_field('usage_idea', 'usage_type', 'Example')
        """
        return (
            Session.query(cls)
            .filter(
                cls.type == form_type, cls.data[field_name].astext == field_value
            )
            .all()
        )

    @classmethod
    def get_filter_by(cls, form_type=None, user_id=None, package_id=None):
        """
        Get submissions filtered by form type, user ID, and/or package ID.

        :param form_type: Optional form type to filter by
        :param user_id: Optional user ID to filter by
        :param package_id: Optional package ID to filter by
        :return: List of FormResponse objects matching the criteria
        """
        query = Session.query(cls)
        if form_type:
            query = query.filter_by(type=form_type)
        if user_id:
            query = query.filter_by(user_id=user_id)
        if package_id:
            query = query.filter_by(package_id=package_id)
        return query.all()

    @classmethod
    def delete(cls, submission_id):
        """Delete a FormResponse by ID"""
        submission = cls.get(submission_id)
        if submission:
            Session.delete(submission)
            Session.commit()
            return True
        return False

    @classmethod
    def update_data(cls, submission_id, new_data):
        """Update the JSONB data of a submission"""
        submission = cls.get(submission_id)
        if submission:
            submission.data = new_data
            Session.commit()
            return submission
        return None

    @classmethod
    def update_data_field(cls, submission_id, field_name, field_value):
        """Update a specific field in the JSONB data"""
        submission = cls.get(submission_id)
        if submission:
            data = submission.data.copy() if submission.data else {}
            data[field_name] = field_value
            submission.data = data
            Session.commit()
            return submission
        return None


