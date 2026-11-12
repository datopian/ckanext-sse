from datetime import datetime, date, timedelta
from collections import OrderedDict

from sqlalchemy import (
    orm, Column, String, Text, DateTime, ForeignKey, Enum, Index, Boolean,
    Integer, CheckConstraint, func, or_, text, inspect as sa_inspect,
)
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

    __tablename__ = "package_access_request"

    id = Column(String(60), primary_key=True, default=make_uuid)
    message = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.now)
    status = Column(
        Enum("pending", "approved", "rejected", "revoked", name="request_status_enum"),
        default="pending",
        nullable=False,
    )
    rejection_message = Column(Text)
    # The organisation the requester said they represent, as typed in the form.
    user_organization = Column(Text)
    approved_or_rejected_by_user_id = Column(String(60), ForeignKey("user.id"))

    package_id = Column(String(60), ForeignKey("package.id"), nullable=False)
    org_id = Column(String(60), ForeignKey("group.id"), nullable=False)
    user_id = Column(String(60), ForeignKey("user.id"), nullable=False)

    package = relationship(Package, foreign_keys=[package_id])
    organization = relationship(Group, foreign_keys=[org_id])
    user = relationship(User, foreign_keys=[user_id])
    approved_or_rejected_by_user = relationship(
        User, foreign_keys=[approved_or_rejected_by_user_id]
    )
    history_rows = relationship(
        "PackageAccessRequestEvent", back_populates="request",
    )

    def __repr__(self):
        return f"<PackageAccessRequest {self.id}>"

    @property
    def events(self):
        """History, oldest first.

        A backfilled decision has no time; it happened after the request was
        made and before anything recorded since, so it sorts at the request's
        own time, after the ``created`` event.
        """
        return sorted(
            self.history_rows,
            key=lambda e: (
                e.created_at or self.created_at or datetime.min,
                e.action != "created",
            ),
        )

    @property
    def last_decision(self):
        """Latest approve/reject/revoke event, or None while pending."""
        decisions = [e for e in self.events if e.action != "created"]
        return decisions[-1] if decisions else None

    @classmethod
    def create(cls, package_id, user_id, org_id, message, user_organization=None):
        """
        Create a new access request.

        :param package_id: ID of the package.
        :param user_id: ID of the user making the request.
        :param org_id: ID of the organization related to the request.
        :param message: Message accompanying the request.
        :param user_organization: Organisation the requester said they represent.
        :return: The created PackageAccessRequest object.
        """
        request = cls(
            package_id=package_id,
            user_id=user_id,
            org_id=org_id,
            message=message,
            user_organization=user_organization,
            status="pending",
        )
        Session.add(request)
        Session.flush()
        PackageAccessRequestEvent.add(request, "created", user_id, message)
        Session.commit()
        return request

    @classmethod
    def add_missing_columns(cls, engine):
        """Add columns introduced after the table was first created. Safe to re-run."""
        existing = {c["name"] for c in sa_inspect(engine).get_columns(cls.__tablename__)}
        if "user_organization" not in existing:
            with engine.begin() as conn:
                conn.execute(text(
                    "ALTER TABLE package_access_request "
                    "ADD COLUMN IF NOT EXISTS user_organization TEXT"))

    @classmethod
    def get(cls, request_id):
        """Get a PackageAccessRequest by ID"""
        return Session.get(cls, request_id)

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
        return (
            Session.query(cls)
            .filter_by(package_id=package_id, user_id=user_id, status=status)
            .all()
        )

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
        return Session.query(cls).filter(PackageAccessRequest.org_id.in_(org_ids)).all()

    STATUSES = ("pending", "approved", "rejected", "revoked")

    @classmethod
    def search(cls, org_ids=None, status=None, q=None, package_id=None,
               org_id=None, requested_from=None, requested_to=None,
               sort="activity", offset=0, limit=25):
        """One page of requests for the dashboard, filtered and sorted in SQL.

        ``org_ids``: organisations the viewer administers (None: all, for
        sysadmins). ``q`` matches the requester's username, full name,
        email or stated organisation. ``requested_from``/``requested_to`` are dates, both inclusive.
        ``sort``: "activity" (latest event first) or "requested" (newest
        request first).

        Returns ``(items, total, status_counts)``; the counts apply every
        filter except the status one.
        """
        last_event = (
            Session.query(
                PackageAccessRequestEvent.request_id.label("request_id"),
                func.max(PackageAccessRequestEvent.created_at).label("at"),
            )
            .group_by(PackageAccessRequestEvent.request_id)
            .subquery()
        )
        activity = func.coalesce(last_event.c.at, cls.created_at)

        query = Session.query(cls).outerjoin(
            last_event, last_event.c.request_id == cls.id)
        if org_ids is not None:
            query = query.filter(cls.org_id.in_(org_ids))
        if org_id:
            query = query.filter(cls.org_id == org_id)
        if package_id:
            query = query.filter(cls.package_id == package_id)
        if requested_from:
            query = query.filter(cls.created_at >= requested_from)
        if requested_to:
            query = query.filter(cls.created_at < requested_to + timedelta(days=1))
        if q:
            like = "%{}%".format(
                q.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_"))
            query = query.join(User, User.id == cls.user_id).filter(or_(
                User.name.ilike(like), User.fullname.ilike(like),
                User.email.ilike(like), cls.user_organization.ilike(like),
            ))

        counts = dict(
            query.with_entities(cls.status, func.count(cls.id))
            .group_by(cls.status).all()
        )
        status_counts = {s: counts.get(s, 0) for s in cls.STATUSES}
        status_counts["all"] = sum(counts.values())

        if status in cls.STATUSES:
            query = query.filter(cls.status == status)
        total = query.count()
        order = cls.created_at if sort == "requested" else activity
        items = (
            query.options(
                orm.joinedload(cls.user), orm.joinedload(cls.package),
                orm.joinedload(cls.organization),
                orm.selectinload(cls.history_rows).joinedload(
                    PackageAccessRequestEvent.actor),
            )
            .order_by(order.desc(), cls.id)
            .offset(offset).limit(limit).all()
        )
        return items, total, status_counts

    @classmethod
    def filter_options(cls, org_ids=None):
        """Datasets and organisations that have requests the viewer can see."""
        query = Session.query(cls)
        if org_ids is not None:
            query = query.filter(cls.org_id.in_(org_ids))
        packages = (
            query.join(Package, Package.id == cls.package_id)
            .with_entities(Package.id, Package.name, Package.title)
            .distinct().all()
        )
        orgs = (
            query.join(Group, Group.id == cls.org_id)
            .with_entities(Group.id, Group.name, Group.title)
            .distinct().all()
        )
        by_title = lambda row: (row.title or row.name).lower()
        return sorted(packages, key=by_title), sorted(orgs, key=by_title)

    @classmethod
    def delete(cls, request_id):
        """Delete a PackageAccessRequest by ID.

        Unused. Would fail while history events reference the request.
        """
        request = cls.get(request_id)
        if request:
            Session.delete(request)
            Session.commit()
            return True
        return False

    @classmethod
    def update_message(cls, request_id, new_message):
        """Update a PackageAccessRequest's message.

        Unused. Records no history event: add one if this is ever wired up.
        """
        request = cls.get(request_id)
        if request:
            request.message = new_message
            Session.commit()
            return request
        return None

    @classmethod
    def update_status(
        cls,
        request_id,
        new_status,
        rejection_message=None,
        approved_or_rejected_by_user_id=None,
    ):
        """Update a PackageAccessRequest's status and optionally rejection message and approved_or_rejected_by_user_id"""
        request = cls.get(request_id)
        if request:
            request.status = new_status
            request.rejection_message = rejection_message
            request.approved_or_rejected_by_user_id = approved_or_rejected_by_user_id
            PackageAccessRequestEvent.add(
                request, new_status, approved_or_rejected_by_user_id,
                rejection_message,
            )
            Session.commit()
            return request
        return None


class PackageAccessRequestEvent(Base):
    """Append-only history of an access request: one row per step.

    The request row only holds the current state, so without this an approval
    followed by a revocation would leave no trace of who approved, or when.
    """

    __tablename__ = "package_access_request_event"

    id = Column(String(60), primary_key=True, default=make_uuid)
    request_id = Column(
        String(60), ForeignKey("package_access_request.id"),
        nullable=False, index=True,
    )
    # created, approved, rejected, revoked
    action = Column(String(20), nullable=False)
    actor_user_id = Column(String(60), ForeignKey("user.id"))
    # The requester's message on created, the admin's reason otherwise.
    reason = Column(Text)
    # Null only for decisions reconstructed from requests made before history
    # was kept, whose time was never stored.
    # No column default: it would also fill the null of a backfilled decision.
    created_at = Column(DateTime)
    backfilled = Column(Boolean, nullable=False, default=False)

    request = relationship(PackageAccessRequest, back_populates="history_rows")
    actor = relationship(User, foreign_keys=[actor_user_id])

    @classmethod
    def add(cls, request, action, actor_user_id, reason=None):
        """Stage an event in the caller's transaction; the caller commits."""
        event = cls(
            request_id=request.id, action=action,
            actor_user_id=actor_user_id, reason=reason,
            created_at=datetime.utcnow(),
        )
        Session.add(event)
        return event

    @classmethod
    def backfill(cls):
        """Seed history for requests that predate it. Safe to re-run.

        Each gets its ``created`` event and, if decided, one event for its
        current state. Earlier decisions were overwritten and are lost.
        """
        seeded = 0
        has_events = Session.query(cls.request_id).distinct()
        for request in Session.query(PackageAccessRequest).filter(
                ~PackageAccessRequest.id.in_(has_events)):
            Session.add(cls(
                request_id=request.id, action="created",
                actor_user_id=request.user_id, reason=request.message,
                created_at=request.created_at, backfilled=True,
            ))
            if request.status != "pending":
                Session.add(cls(
                    request_id=request.id, action=request.status,
                    actor_user_id=request.approved_or_rejected_by_user_id,
                    reason=request.rejection_message,
                    created_at=None, backfilled=True,
                ))
            seeded += 1
        Session.commit()
        return seeded


class UserPasswordHistory(tk.BaseModel):
    """One row per password a user has held, newest last.

    Serves both halves of the password policy: the newest row's
    ``created_at`` is when the password was last changed, which is what the
    rotation window is measured from, and the stored hashes are what a
    proposed new password is checked against for reuse.

    The hash is copied from ``user.password`` rather than re-derived, so a row
    is only ever as strong as CKAN's own storage -- pbkdf2-sha512 at the
    rounds in force when it was set. Rows beyond the configured history length
    are deleted rather than kept, so no more old credential material is
    retained than the policy actually needs.

    There is no unique constraint on ``(user_id, password_hash)``: pbkdf2
    salts every hash, so the same password set twice produces two different
    hashes and the database cannot recognise the repeat. Reuse is caught by
    verifying the candidate against each stored hash instead -- see
    ``ckanext.sse.password_policy.is_reused``.
    """

    __tablename__ = "user_password_history"
    __table_args__ = (
        # Every lookup is "the newest rows for this user", so the ordering
        # column belongs in the index. Without it this is a sort per
        # authenticated page request.
        Index(
            "idx_user_password_history_user_created",
            "user_id",
            "created_at",
        ),
    )

    id = Column(Unicode(64), primary_key=True, default=make_uuid)
    user_id = Column(String(60), ForeignKey("user.id"), nullable=False)
    # Not String(n): the hash length is passlib's to decide, and it has grown
    # before now.
    password_hash = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship(User, foreign_keys=[user_id])

    def __repr__(self):
        return f"<UserPasswordHistory {self.user_id} {self.created_at}>"


class FormResponse(DomainObject.DomainObject, tk.BaseModel):
    """
    Generic model for storing dynamic form submissions using JSONB.
    This can handle usage ideas, usage example feedback forms, or any other dynamic forms response.
    """

    __tablename__ = "form_response"

    id = Column(Unicode(64), primary_key=True, default=make_uuid)
    type = Column(String(100), nullable=False)
    submitted_at = Column(DateTime, default=datetime.utcnow)
    data = Column(JSONB, nullable=False)
    user_id = Column(String(60), ForeignKey("user.id"), nullable=True)
    state = Column(String(100), nullable=False)
    package_id = Column(String(60), ForeignKey("package.id"), nullable=True)
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
    def create(cls, **kwargs):
        """
        Generic create method for any form type.

        :param form_type: Type of form (e.g., 'usage_idea', 'feedback', 'contact')
        :param form_data: Dictionary containing the form data
        :param user_id: Optional user ID
        :param package_id: Optional package/dataset ID
        :return: The created FormResponse object
        """
        submission = cls(**kwargs)
        Session.add(submission)
        Session.commit()
        return submission

    @classmethod
    def get(cls, id, include_all=False):
        """Get a FormResponse by ID"""
        if include_all:
            return Session.get(cls, id)
        else:
            return (
                Session.query(cls)
                .filter_by(id=id, state="approved")
                .one_or_none()
            )

    @classmethod
    def get_all(cls, include_all=False):
        """Get all FormResponses"""
        if include_all:
            return Session.query(cls).order_by(cls.submitted_at.desc()).all()
        else:
            return (
                Session.query(cls)
                .filter_by(state="approved")
                .order_by(cls.submitted_at.desc())
                .all()
            )

    @classmethod
    def get_by_form_type(cls, form_type, include_all=False):
        """Get all submissions by form type"""
        if include_all:
            return Session.query(cls).filter_by(type=form_type).all()
        else:
            return Session.query(cls).filter_by(type=form_type, state="approved").all()

    @classmethod
    def get_by_user(cls, user_id, include_all=False):
        """Get all submissions from a specific user"""
        if include_all:
            return Session.query(cls).filter_by(user_id=user_id).all()
        else:
            return Session.query(cls).filter_by(user_id=user_id, state="approved").all()

    @classmethod
    def get_by_package(cls, package_id, include_all=False):
        """Get all submissions related to a specific package/dataset"""
        if include_all:
            return Session.query(cls).filter_by(package_id=package_id).all()
        else:
            return (
                Session.query(cls)
                .filter_by(package_id=package_id, state="approved")
                .all()
            )

    @classmethod
    def get_by_data_field(cls, form_type, field_name, field_value, include_all=False):
        """
        Query submissions by a specific field in the JSONB data.

        Example: get_by_data_field('usage_idea', 'usage_type', 'Example')
        """
        if include_all:
            return (
                Session.query(cls)
                .filter(
                    cls.type == form_type, cls.data[field_name].astext == field_value
                )
                .all()
            )
        else:
            return (
                Session.query(cls)
                .filter(
                    cls.type == form_type,
                    cls.data[field_name].astext == field_value,
                    cls.state == "approved",
                )
                .all()
            )

    @classmethod
    def get_filter_by(
        cls, form_type=None, user_id=None, package_id=None, include_all=False
    ):
        """
        Get submissions filtered by form type, user ID, and/or package ID.

        :param form_type: Optional form type to filter by
        :param user_id: Optional user ID to filter by
        :param package_id: Optional package ID to filter by
        :param include_all: If True, include all submissions regardless of state
        :return: List of FormResponse objects matching the criteria
        """
        query = Session.query(cls)
        if form_type:
            query = query.filter_by(type=form_type)
        if user_id:
            query = query.filter_by(user_id=user_id)
        if package_id:
            query = query.filter_by(package_id=package_id)
        if not include_all:
            query = query.filter_by(state="approved")
        return query.all()

    @classmethod
    def delete(cls, submission_id):
        """Delete a FormResponse by ID"""
        submission = cls.get(submission_id, include_all=True)
        if submission:
            Session.delete(submission)
            Session.commit()
            return True
        return False

    @classmethod
    def update(cls, submission_id, **kwargs):
        """Update a FormResponse by ID"""
        submission = cls.get(submission_id, include_all=True)
        if submission:
            for key, value in kwargs.items():
                setattr(submission, key, value)
            Session.commit()
            return submission
        return None

    @classmethod
    def update_data(cls, submission_id, new_data):
        """Update the JSONB data of a submission"""
        submission = cls.get(submission_id, include_all=True)
        if submission:
            submission.data = new_data
            Session.commit()
            return submission
        return None

    @classmethod
    def update_data_field(cls, submission_id, field_name, field_value):
        """Update a specific field in the JSONB data"""
        submission = cls.get(submission_id, include_all=True)
        if submission:
            data = submission.data.copy() if submission.data else {}
            data[field_name] = field_value
            submission.data = data
            Session.commit()
            return submission
        return None


class Dashboard(DomainObject.DomainObject, tk.BaseModel):
    """A dashboard owned either by a user (personal) or by a dataset."""

    __tablename__ = "sse_dashboard"
    __table_args__ = (
        CheckConstraint(
            "(owner_user_id IS NULL) <> (package_id IS NULL)",
            name="sse_dashboard_one_owner",
        ),
        CheckConstraint(
            "visibility IN ('private', 'public')",
            name="sse_dashboard_visibility",
        ),
        Index("idx_sse_dashboard_owner_user_id", "owner_user_id"),
        Index("idx_sse_dashboard_package_id", "package_id"),
        Index(
            "uq_sse_dashboard_package_slug", "package_id", "slug",
            unique=True, postgresql_where=text("package_id IS NOT NULL"),
        ),
    )

    id = Column(Unicode(64), primary_key=True, default=make_uuid)
    title = Column(Text, nullable=False)
    slug = Column(Unicode(100), nullable=True)
    description = Column(Text, nullable=True)
    # Hard user removal takes their personal dashboards with it; CKAN's own
    # user_delete only marks the account deleted, so they are kept then.
    owner_user_id = Column(
        String(60), ForeignKey("user.id", ondelete="CASCADE"), nullable=True)
    # Purging a dataset removes its dashboards.
    package_id = Column(
        String(60), ForeignKey("package.id", ondelete="CASCADE"), nullable=True)
    visibility = Column(String(20), nullable=False, default="private")
    position = Column(Integer, nullable=False, default=0)
    config = Column(JSONB, nullable=False)
    created_by = Column(
        String(60), ForeignKey("user.id", ondelete="SET NULL"), nullable=True)
    updated_by = Column(
        String(60), ForeignKey("user.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    def as_dict(self):
        out = OrderedDict()
        for col in orm.class_mapper(self.__class__).mapped_table.c:
            val = getattr(self, col.name)
            if isinstance(val, datetime):
                val = val.isoformat()
            out[col.name] = val
        return out

    @classmethod
    def get(cls, dashboard_id):
        return Session.get(cls, dashboard_id)

    @classmethod
    def for_user(cls, user_id):
        return (
            Session.query(cls)
            .filter_by(owner_user_id=user_id)
            .order_by(cls.updated_at.desc())
            .all()
        )

    @classmethod
    def for_package(cls, package_id):
        """A data asset's dashboards in the order its editors set."""
        return (
            Session.query(cls)
            .filter_by(package_id=package_id)
            .order_by(cls.position.asc(), cls.created_at.asc())
            .all()
        )

    @classmethod
    def by_slug(cls, package_id, slug):
        return Session.query(cls).filter_by(package_id=package_id, slug=slug).first()

    @classmethod
    def showcased(cls):
        return Session.query(cls).filter(cls.package_id.isnot(None)).all()
