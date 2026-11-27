"""resource_activity_list scans a bounded window, and stops at its time budget."""

import pytest

import ckan.plugins.toolkit as tk

import ckanext.sse.action as sse_action


def _activities(n):
    return [{"id": f"a{i}", "data": {"package": {"id": "p"}}} for i in range(n)]


@pytest.fixture
def stubbed(monkeypatch):
    seen = {}

    def fake_get_action(name):
        if name == "dashboard_activity_list":
            def dash(context, data_dict):
                seen["limit"] = data_dict["limit"]
                return _activities(5)
            return dash
        if name == "activity_diff":
            def diff(context, data_dict):
                seen.setdefault("diffs", 0)
                seen["diffs"] += 1
                raise RuntimeError("no diff in this test")
            return diff
        raise AssertionError(name)

    monkeypatch.setattr(tk, "get_action", fake_get_action)
    return seen


def test_default_window_is_bounded(stubbed):
    sse_action.resource_activity_list({}, {})
    assert stubbed["limit"] == sse_action.DEFAULT_ACTIVITY_SCAN_LIMIT


def test_caller_can_ask_for_a_different_window(stubbed):
    sse_action.resource_activity_list({}, {"limit": 7})
    assert stubbed["limit"] == 7


def test_stops_at_the_time_budget(stubbed, monkeypatch):
    monkeypatch.setattr(sse_action, "ACTIVITY_DIFF_TIME_BUDGET_SECONDS", -1)
    sse_action.resource_activity_list({}, {})
    assert stubbed.get("diffs", 0) == 0
