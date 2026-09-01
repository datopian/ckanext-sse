"""Shared fixtures.

``clean_db`` drops every table and rebuilds CKAN's own, which leaves this
extension's behind: in production they are created by ``SsePlugin.configure``,
which has already run by the time a test asks for a clean database. Tests that
touch them therefore have to put them back, and doing it here rather than in
each test file keeps the suite independent of the order its files run in.
"""

import pytest

from ckan.model.meta import engine

from ckanext.sse.model import (
    FormResponse,
    PackageAccessRequest,
    UserPasswordHistory,
)

EXTENSION_TABLES = (
    PackageAccessRequest,
    FormResponse,
    UserPasswordHistory,
)


@pytest.fixture
def sse_tables(clean_db):
    """A clean database with this extension's tables present."""
    for model in EXTENSION_TABLES:
        model.__table__.create(engine, checkfirst=True)
    return engine
