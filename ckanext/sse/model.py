from datetime import datetime
from sqlalchemy import Column, String, Text, DateTime, ForeignKey, Enum
from sqlalchemy.orm import relationship
from ckan.model.meta import metadata, Session
from ckan.model.types import make_uuid
from sqlalchemy.ext.declarative import declarative_base

from ckan.model.package import Package
from ckan.model.group import Group
from ckan.model.user import User

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
        PackageAccessRequest.US
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
