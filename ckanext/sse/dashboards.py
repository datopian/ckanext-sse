"""Dashboards: storage actions, access rules and config validation.

A dashboard is a list of rows, each holding 1 to 3 widgets (chart, KPI card,
map or text), plus dashboard-wide filters that widgets bind to by column.
The portal builds the queries; this module keeps what is stored well formed
and limited to data every signed-in user may read.
"""
import json
import re
from datetime import datetime

import ckan.plugins.toolkit as tk
from ckan import model

from .model import Dashboard

SCHEMA_VERSION = 1

MAX_CONFIG_BYTES = 256 * 1024
MAX_TITLE_CHARS = 200
MAX_DESCRIPTION_CHARS = 1000
MAX_LABEL_CHARS = 200
MAX_TEXT_CHARS = 5000
MAX_FILTERS = 10
MAX_FILTER_OPTIONS = 50
MAX_WIDGET_FILTERS = 20
MAX_MAP_LAYERS = 10
MAX_TOOLTIP_FIELDS = 10

ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

CHART_TYPES = frozenset({
    "bar", "bar_horizontal", "bar_stacked", "bar_stacked_100",
    "line", "area", "area_stacked", "scatter", "pie", "donut", "heatmap",
})
AGGREGATES = frozenset({"SUM", "AVG", "COUNT"})
OPERATORS = frozenset({"=", "!=", ">", ">=", "<", "<="})
SORT_BY = frozenset({"data", "labels"})
# Periods a chart's date axis can be grouped by (date_trunc in the portal's SQL).
DATE_GROUPS = frozenset({"day", "week", "month", "quarter", "year"})
SORT_ORDER = frozenset({"ASC", "DESC"})
RELATIVE_WINDOWS = frozenset({
    "last_7_days", "last_30_days", "last_12_months", "year_to_date",
})
KPI_STYLES = frozenset({"number", "gauge", "change"})
DATE_TYPES = frozenset({"date", "timestamp", "timestamptz"})


# Access

def _user_obj(context):
    user_obj = context.get("auth_user_obj")
    # check_access only fills auth_user_obj when auth is not skipped.
    if user_obj is None and context.get("user"):
        user_obj = model.User.by_name(context["user"])
    if user_obj is None or getattr(user_obj, "is_anonymous", False):
        return None
    return user_obj


def _signed_in(context):
    if _user_obj(context) is None:
        return {"success": False, "msg": tk._("Sign in to use dashboards")}
    return {"success": True}


def _owner_only(context, data_dict):
    user_obj = _user_obj(context)
    if user_obj is None:
        return {"success": False, "msg": tk._("Sign in to use dashboards")}
    dashboard = Dashboard.get(data_dict.get("id") or "")
    # Unknown ids are left to the action, which answers 404.
    if dashboard is None:
        return {"success": True}
    if dashboard.owner_user_id and dashboard.owner_user_id == user_obj.id:
        return {"success": True}
    return {"success": False}


def auth_create(context, data_dict):
    return _signed_in(context)


def auth_list(context, data_dict):
    result = _signed_in(context)
    if not result["success"]:
        return result
    user_id = data_dict.get("user_id")
    if user_id and user_id != _user_obj(context).id:
        return {"success": False}
    return result


def auth_show(context, data_dict):
    return _owner_only(context, data_dict)


def auth_update(context, data_dict):
    return _owner_only(context, data_dict)


def auth_delete(context, data_dict):
    return _owner_only(context, data_dict)


# Config validation

class _Errors(list):
    def add(self, path, msg):
        self.append("{}: {}".format(path, msg))


def _is_str(value, max_len=None, required=True):
    if value is None or value == "":
        return not required
    return isinstance(value, str) and (max_len is None or len(value) <= max_len)


def _is_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _check_id(errors, path, value, seen):
    if not isinstance(value, str) or not ID_RE.match(value):
        errors.add(path, "must be 1-64 letters, digits, '-' or '_'")
    elif value in seen:
        errors.add(path, "duplicate id '{}'".format(value))
    else:
        seen.add(value)


class _Resources(object):
    """Looks up each referenced resource once."""

    def __init__(self):
        self._cache = {}

    def get(self, resource_id):
        if resource_id not in self._cache:
            self._cache[resource_id] = self._load(resource_id)
        return self._cache[resource_id]

    @staticmethod
    def _load(resource_id):
        resource = model.Resource.get(resource_id)
        if resource is None or resource.state != "active":
            return {"error": "resource not found"}
        package = resource.package
        if not eligible_package(package):
            return {"error": "data is not available to every signed-in user"}
        fields = None
        if resource.extras.get("datastore_active") in (True, "true", "True"):
            try:
                result = tk.get_action("datastore_search")(
                    {"ignore_auth": True},
                    {"resource_id": resource.id, "limit": 0},
                )
                fields = {f["id"]: f["type"] for f in result["fields"]}
            except (KeyError, tk.ObjectNotFound, tk.ValidationError):
                fields = None
        return {
            "format": (resource.format or "").lower().replace(" ", ""),
            "url": resource.url or "",
            "fields": fields,
        }


def eligible_package(package):
    """Data every signed-in user may read: active, public, not restricted."""
    if package is None or package.state != "active" or package.private:
        return False
    return not tk.asbool(package.extras.get("is_restricted") or False)


def _check_tabular(errors, path, widget, resources):
    """Resource must be in the DataStore; returns its fields or None."""
    resource_id = widget.get("resource_id")
    if not _is_str(resource_id, 100):
        errors.add(path + ".resource_id", "is required")
        return None
    info = resources.get(resource_id)
    if "error" in info:
        errors.add(path + ".resource_id", info["error"])
        return None
    if info["fields"] is None:
        errors.add(path + ".resource_id", "has no tabular data in the DataStore")
        return None
    return info["fields"]


def _check_column(errors, path, column, fields, required=True):
    if column is None or column == "":
        if required:
            errors.add(path, "is required")
        return
    if not isinstance(column, str):
        errors.add(path, "must be a column name")
    elif fields is not None and column not in fields:
        errors.add(path, "unknown column '{}'".format(column))


def _check_fixed_filters(errors, path, filters, fields):
    if filters is None:
        return
    if not isinstance(filters, list) or len(filters) > MAX_WIDGET_FILTERS:
        errors.add(path, "must be a list of at most {}".format(MAX_WIDGET_FILTERS))
        return
    for i, f in enumerate(filters):
        fpath = "{}[{}]".format(path, i)
        if not isinstance(f, dict):
            errors.add(fpath, "must be an object")
            continue
        _check_column(errors, fpath + ".column", f.get("column"), fields)
        if f.get("operation") not in OPERATORS:
            errors.add(fpath + ".operation", "must be one of " + ", ".join(sorted(OPERATORS)))
        value = f.get("value")
        if not (_is_str(value, MAX_LABEL_CHARS) or _is_number(value)):
            errors.add(fpath + ".value", "is required")


def _check_bindings(errors, path, bindings, fields, filters):
    if bindings is None:
        return
    if not isinstance(bindings, dict):
        errors.add(path, "must be an object")
        return
    for filter_id, column in bindings.items():
        bpath = "{}.{}".format(path, filter_id)
        if filter_id not in filters:
            errors.add(bpath, "unknown dashboard filter")
            continue
        _check_column(errors, bpath, column, fields)
        if (
            filters[filter_id] == "relative_date"
            and fields is not None
            and column in fields
            and fields[column] not in DATE_TYPES
        ):
            errors.add(bpath, "relative date filters need a date or timestamp column")


def _check_chart(errors, path, widget, resources, filters):
    fields = _check_tabular(errors, path, widget, resources)
    query = widget.get("query")
    chart = widget.get("chart")
    if not isinstance(query, dict):
        errors.add(path + ".query", "must be an object")
        query = {}
    if not isinstance(chart, dict):
        errors.add(path + ".chart", "must be an object")
        chart = {}
    if chart.get("chartType") not in CHART_TYPES:
        errors.add(path + ".chart.chartType", "must be one of " + ", ".join(sorted(CHART_TYPES)))
    _check_column(errors, path + ".query.dimension", query.get("dimension"), fields)
    _check_column(errors, path + ".query.measure", query.get("measure"), fields)
    _check_column(errors, path + ".query.category", query.get("category"), fields, required=False)
    date_group = query.get("date_group")
    if date_group not in (None, ""):
        if date_group not in DATE_GROUPS:
            errors.add(path + ".query.date_group", "must be one of " + ", ".join(sorted(DATE_GROUPS)))
        elif fields is not None and fields.get(query.get("dimension")) not in DATE_TYPES:
            errors.add(path + ".query.date_group", "needs a date or timestamp dimension")
    if query.get("aggregate") not in (None, "") and query.get("aggregate") not in AGGREGATES:
        errors.add(path + ".query.aggregate", "must be one of SUM, AVG, COUNT or empty")
    _check_fixed_filters(errors, path + ".query.filters", query.get("filters"), fields)
    sorting = chart.get("sorting") or {}
    if not isinstance(sorting, dict):
        errors.add(path + ".chart.sorting", "must be an object")
    else:
        if sorting.get("by") not in (None, "") and sorting.get("by") not in SORT_BY:
            errors.add(path + ".chart.sorting.by", "must be data or labels")
        if sorting.get("order") not in (None, "") and sorting.get("order") not in SORT_ORDER:
            errors.add(path + ".chart.sorting.order", "must be ASC or DESC")
    if not _is_str(widget.get("title"), MAX_LABEL_CHARS, required=False):
        errors.add(path + ".title", "is too long")
    _check_bindings(errors, path + ".filter_bindings", widget.get("filter_bindings"), fields, filters)


def _check_kpi(errors, path, widget, resources, filters):
    fields = _check_tabular(errors, path, widget, resources)
    query = widget.get("query")
    if not isinstance(query, dict):
        errors.add(path + ".query", "must be an object")
        query = {}
    _check_column(errors, path + ".query.measure", query.get("measure"), fields)
    if query.get("aggregate") not in AGGREGATES:
        errors.add(path + ".query.aggregate", "must be one of SUM, AVG, COUNT")
    _check_fixed_filters(errors, path + ".query.filters", query.get("filters"), fields)
    if not _is_str(widget.get("label"), MAX_LABEL_CHARS):
        errors.add(path + ".label", "is required")
    style = widget.get("style")
    if not isinstance(style, dict) or style.get("kind") not in KPI_STYLES:
        errors.add(path + ".style.kind", "must be one of number, gauge, change")
    else:
        for key in ("min", "max", "target", "reference"):
            if style.get(key) is not None and not _is_number(style.get(key)):
                errors.add(path + ".style." + key, "must be a number")
        if style["kind"] == "gauge" and style.get("target") is None and (
            style.get("min") is None or style.get("max") is None
        ):
            errors.add(path + ".style", "a gauge needs a minimum and maximum, or a target")
        if style["kind"] == "change" and style.get("reference") is None:
            errors.add(path + ".style.reference", "is required")
    _check_bindings(errors, path + ".filter_bindings", widget.get("filter_bindings"), fields, filters)


def _check_map(errors, path, widget, resources, filters):
    layers = widget.get("layers")
    if not isinstance(layers, list) or not 1 <= len(layers) <= MAX_MAP_LAYERS:
        errors.add(path + ".layers", "must be a list of 1 to {}".format(MAX_MAP_LAYERS))
        return
    seen = set()
    for i, layer in enumerate(layers):
        lpath = "{}.layers[{}]".format(path, i)
        if not isinstance(layer, dict):
            errors.add(lpath, "must be an object")
            continue
        _check_id(errors, lpath + ".id", layer.get("id"), seen)
        tooltip = layer.get("tooltip") or []
        if not isinstance(tooltip, list) or len(tooltip) > MAX_TOOLTIP_FIELDS:
            errors.add(lpath + ".tooltip", "must be a list of at most {}".format(MAX_TOOLTIP_FIELDS))
            tooltip = []
        kind = layer.get("kind")
        if kind == "points":
            fields = _check_tabular(errors, lpath, layer, resources)
            _check_column(errors, lpath + ".lat", layer.get("lat"), fields)
            _check_column(errors, lpath + ".lon", layer.get("lon"), fields)
            for j, column in enumerate(tooltip):
                _check_column(errors, "{}.tooltip[{}]".format(lpath, j), column, fields)
            _check_bindings(errors, lpath + ".filter_bindings", layer.get("filter_bindings"), fields, filters)
        elif kind == "geojson":
            resource_id = layer.get("resource_id")
            if not _is_str(resource_id, 100):
                errors.add(lpath + ".resource_id", "is required")
                continue
            info = resources.get(resource_id)
            if "error" in info:
                errors.add(lpath + ".resource_id", info["error"])
                continue
            if "geojson" not in info["format"] and not info["url"].lower().endswith(".geojson"):
                errors.add(lpath + ".resource_id", "is not a GeoJSON resource")
            for j, prop in enumerate(tooltip):
                if not _is_str(prop, MAX_LABEL_CHARS):
                    errors.add("{}.tooltip[{}]".format(lpath, j), "must be a property name")
            # GeoJSON properties are not known here; the column is only checked for shape.
            _check_bindings(errors, lpath + ".filter_bindings", layer.get("filter_bindings"), None, filters)
        else:
            errors.add(lpath + ".kind", "must be points or geojson")


def _check_text(errors, path, widget):
    if not _is_str(widget.get("markdown"), MAX_TEXT_CHARS):
        errors.add(path + ".markdown", "is required, up to {} characters".format(MAX_TEXT_CHARS))


def _check_filters(errors, filters):
    """Returns {filter_id: type} for the widgets to bind against."""
    if filters is None:
        return {}
    if not isinstance(filters, list) or len(filters) > MAX_FILTERS:
        errors.add("filters", "must be a list of at most {}".format(MAX_FILTERS))
        return {}
    types = {}
    seen = set()
    for i, f in enumerate(filters):
        path = "filters[{}]".format(i)
        if not isinstance(f, dict):
            errors.add(path, "must be an object")
            continue
        _check_id(errors, path + ".id", f.get("id"), seen)
        if not _is_str(f.get("label"), MAX_LABEL_CHARS):
            errors.add(path + ".label", "is required")
        kind = f.get("type")
        if kind not in ("value", "relative_date"):
            errors.add(path + ".type", "must be value or relative_date")
            continue
        options = f.get("options")
        if not isinstance(options, list) or not 1 <= len(options) <= MAX_FILTER_OPTIONS:
            errors.add(path + ".options", "must be a list of 1 to {}".format(MAX_FILTER_OPTIONS))
            continue
        option_ids = set()
        for j, option in enumerate(options):
            opath = "{}.options[{}]".format(path, j)
            if not isinstance(option, dict):
                errors.add(opath, "must be an object")
                continue
            _check_id(errors, opath + ".id", option.get("id"), option_ids)
            if not _is_str(option.get("label"), MAX_LABEL_CHARS):
                errors.add(opath + ".label", "is required")
            if option.get("all") is True:
                continue
            if kind == "value":
                value = option.get("value")
                if not (_is_str(value, MAX_LABEL_CHARS) or _is_number(value)):
                    errors.add(opath + ".value", "is required")
            elif option.get("window") not in RELATIVE_WINDOWS:
                errors.add(opath + ".window", "must be one of " + ", ".join(sorted(RELATIVE_WINDOWS)))
        if f.get("default_option") not in option_ids:
            errors.add(path + ".default_option", "must be one of the filter's option ids")
        if isinstance(f.get("id"), str):
            types[f["id"]] = kind
    return types


def validate_config(config):
    """Raise ValidationError listing every problem in a dashboard config."""
    errors = _Errors()
    if not isinstance(config, dict):
        raise tk.ValidationError({"config": ["must be an object"]})
    if len(json.dumps(config)) > MAX_CONFIG_BYTES:
        raise tk.ValidationError({"config": ["is larger than {} bytes".format(MAX_CONFIG_BYTES)]})
    if config.get("schema_version") != SCHEMA_VERSION:
        errors.add("schema_version", "must be {}".format(SCHEMA_VERSION))

    filters = _check_filters(errors, config.get("filters"))
    resources = _Resources()

    rows = config.get("rows")
    if not isinstance(rows, list):
        errors.add("rows", "must be a list")
        rows = []
    row_ids, widget_ids = set(), set()
    for i, row in enumerate(rows):
        rpath = "rows[{}]".format(i)
        if not isinstance(row, dict):
            errors.add(rpath, "must be an object")
            continue
        _check_id(errors, rpath + ".id", row.get("id"), row_ids)
        columns = row.get("columns")
        if columns not in (1, 2, 3):
            errors.add(rpath + ".columns", "must be 1, 2 or 3")
            continue
        cells = row.get("cells")
        if not isinstance(cells, list) or len(cells) != columns:
            errors.add(rpath + ".cells", "must have one entry per column")
            continue
        for j, widget in enumerate(cells):
            wpath = "{}.cells[{}]".format(rpath, j)
            if widget is None:
                continue
            if not isinstance(widget, dict):
                errors.add(wpath, "must be a widget or null")
                continue
            _check_id(errors, wpath + ".id", widget.get("id"), widget_ids)
            kind = widget.get("type")
            if kind == "chart":
                _check_chart(errors, wpath, widget, resources, filters)
            elif kind == "kpi":
                _check_kpi(errors, wpath, widget, resources, filters)
            elif kind == "map":
                if columns == 3:
                    errors.add(wpath, "maps can only be placed in 1 or 2 column rows")
                _check_map(errors, wpath, widget, resources, filters)
            elif kind == "text":
                _check_text(errors, wpath, widget)
            else:
                errors.add(wpath + ".type", "must be chart, kpi, map or text")

    if errors:
        raise tk.ValidationError({"config": list(errors)})


def _check_texts(data_dict, require_title):
    errors = {}
    title = data_dict.get("title")
    if require_title or "title" in data_dict:
        if not isinstance(title, str) or not title.strip() or len(title) > MAX_TITLE_CHARS:
            errors["title"] = ["is required, up to {} characters".format(MAX_TITLE_CHARS)]
    description = data_dict.get("description")
    if description is not None and (
        not isinstance(description, str) or len(description) > MAX_DESCRIPTION_CHARS
    ):
        errors["description"] = ["must be up to {} characters".format(MAX_DESCRIPTION_CHARS)]
    if errors:
        raise tk.ValidationError(errors)


def _parse_config(data_dict):
    config = data_dict.get("config")
    if isinstance(config, str):
        try:
            config = json.loads(config)
        except ValueError:
            raise tk.ValidationError({"config": ["is not valid JSON"]})
    return config


def _require_user(context):
    user_obj = _user_obj(context)
    if user_obj is None:
        raise tk.NotAuthorized(tk._("Sign in to use dashboards"))
    return user_obj


def _get_or_404(data_dict):
    dashboard = Dashboard.get(tk.get_or_bust(data_dict, "id"))
    if dashboard is None:
        raise tk.ObjectNotFound(tk._("Dashboard not found"))
    return dashboard


# Actions

def dashboard_create(context, data_dict):
    """Create a personal dashboard for the signed-in user.

    :param title: up to 200 characters
    :param description: optional, up to 1000 characters
    :param config: the dashboard layout, widgets and filters (object or JSON)
    """
    tk.check_access("sse_dashboard_create", context, data_dict)
    _check_texts(data_dict, require_title=True)
    config = _parse_config(data_dict)
    validate_config(config)

    user_id = _require_user(context).id
    now = datetime.utcnow()
    dashboard = Dashboard(
        title=data_dict["title"].strip(),
        description=data_dict.get("description") or None,
        owner_user_id=user_id,
        config=config,
        created_by=user_id,
        updated_by=user_id,
        created_at=now,
        updated_at=now,
    )
    model.Session.add(dashboard)
    model.Session.commit()
    return dashboard.as_dict()


@tk.side_effect_free
def dashboard_show(context, data_dict):
    """Show a dashboard.

    :param id: the dashboard id
    """
    tk.check_access("sse_dashboard_show", context, data_dict)
    return _get_or_404(data_dict).as_dict()


@tk.side_effect_free
def _layout(config):
    rows = (config or {}).get("rows") or []
    return [
        [cell.get("type") if isinstance(cell, dict) else None for cell in (row.get("cells") or [])]
        for row in rows
        if isinstance(row, dict)
    ]


def dashboard_list(context, data_dict):
    """List the signed-in user's personal dashboards, most recently updated first.

    Configs are left out; ``sse_dashboard_show`` returns them. Each item has
    a ``layout`` instead: the widget type in each cell, row by row (``None``
    for an empty cell), enough to draw a thumbnail.

    :param user_id: sysadmins only, list another user's dashboards
    """
    tk.check_access("sse_dashboard_list", context, data_dict)
    user_id = data_dict.get("user_id") or _require_user(context).id
    out = []
    for dashboard in Dashboard.for_user(user_id):
        item = dashboard.as_dict()
        item["layout"] = _layout(item.pop("config"))
        out.append(item)
    return out


def dashboard_update(context, data_dict):
    """Update a dashboard. Only the fields passed are changed.

    :param id: the dashboard id
    :param title: optional
    :param description: optional
    :param config: optional, replaces the whole config
    """
    tk.check_access("sse_dashboard_update", context, data_dict)
    dashboard = _get_or_404(data_dict)
    _check_texts(data_dict, require_title=False)
    if "config" in data_dict:
        config = _parse_config(data_dict)
        validate_config(config)
        dashboard.config = config
    if "title" in data_dict:
        dashboard.title = data_dict["title"].strip()
    if "description" in data_dict:
        dashboard.description = data_dict.get("description") or None
    dashboard.updated_by = _require_user(context).id
    dashboard.updated_at = datetime.utcnow()
    model.Session.commit()
    return dashboard.as_dict()


def dashboard_delete(context, data_dict):
    """Delete a dashboard permanently.

    :param id: the dashboard id
    """
    tk.check_access("sse_dashboard_delete", context, data_dict)
    dashboard = _get_or_404(data_dict)
    model.Session.delete(dashboard)
    model.Session.commit()


def get_actions():
    return {
        "sse_dashboard_create": dashboard_create,
        "sse_dashboard_show": dashboard_show,
        "sse_dashboard_list": dashboard_list,
        "sse_dashboard_update": dashboard_update,
        "sse_dashboard_delete": dashboard_delete,
    }


def get_auth_functions():
    return {
        "sse_dashboard_create": auth_create,
        "sse_dashboard_show": auth_show,
        "sse_dashboard_list": auth_list,
        "sse_dashboard_update": auth_update,
        "sse_dashboard_delete": auth_delete,
    }
