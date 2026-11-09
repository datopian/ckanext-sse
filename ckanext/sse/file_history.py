"""Every file a resource has had, read back from the dataset's activity history.

ckanext-s3filestore-with-ui never overwrites or deletes a stored file, so each
saved version of a dataset in the activity stream still points at the file it
had, by name. This module turns those snapshots into a per-resource list of
files with when they were uploaded, by whom, and their SHA-256, and records the
activity that puts a direct upload's checksum into that history.
"""

import logging
import os

import ckan.model as model
import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit

from .upload_security import CHECKSUM_FIELD

log = logging.getLogger(__name__)

PACKAGE_ACTIVITY_TYPES = ("new package", "changed package")


def _activity_model():
    if not plugins.plugin_loaded("activity"):
        return None
    from ckanext.activity.model import Activity

    return Activity


def record_checksum_activity(package_id):
    """Add a "changed package" activity for a checksum written after the save.

    A file sent straight to the bucket is hashed later by the scan job, which
    writes the result directly to the resource. Without a new activity the
    history would only show the file with its checksum still pending. Built
    by the same function CKAN uses for every dataset change, as the site user.
    """
    Activity = _activity_model()
    package = model.Package.get(package_id)
    if Activity is None or package is None or package.private:
        # CKAN keeps no activity history for private datasets.
        return None
    site_user = toolkit.get_action("get_site_user")({"ignore_auth": True}, {})
    user = model.User.get(site_user["name"])
    activity = Activity.activity_stream_item(package, "changed", user.id)
    if activity is None:
        return None
    model.Session.add(activity)
    model.Session.commit()
    return activity


def resource_file_history(package_id, resource_id):
    """Files of an uploaded resource, newest first.

    Each item: ``filename``, ``url`` (download link, as stored in the
    snapshot), ``sha256`` (empty while unknown), ``size``, ``uploaded_at``
    (first snapshot with the file), ``uploaded_by`` and ``current``.
    """
    Activity = _activity_model()
    if Activity is None:
        return []
    activities = (
        model.Session.query(Activity)
        .filter(
            Activity.object_id == package_id,
            Activity.activity_type.in_(PACKAGE_ACTIVITY_TYPES),
        )
        .order_by(Activity.timestamp.asc())
        .all()
    )
    files, order, current = {}, [], None
    for activity in activities:
        package = (activity.data or {}).get("package") or {}
        resource = next(
            (r for r in package.get("resources") or [] if r.get("id") == resource_id),
            None,
        )
        if not resource or resource.get("url_type") != "upload":
            current = None
            continue
        url = resource.get("url") or ""
        filename = os.path.basename(url.split("?")[0])
        if not filename:
            continue
        entry = files.get(filename)
        if entry is None:
            entry = files[filename] = {
                "filename": filename,
                "url": url,
                "sha256": "",
                "size": resource.get("size"),
                "uploaded_at": activity.timestamp,
                "uploaded_by": (activity.data or {}).get("actor"),
            }
            order.append(filename)
        # A direct upload's checksum arrives in a later snapshot of the same file.
        if resource.get(CHECKSUM_FIELD):
            entry["sha256"] = resource[CHECKSUM_FIELD]
        if resource.get("size"):
            entry["size"] = resource["size"]
        current = filename
    return [
        dict(files[name], current=(name == current)) for name in reversed(order)
    ]
