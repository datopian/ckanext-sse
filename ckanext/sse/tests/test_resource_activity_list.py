"""resource_activity_* scan a bounded window, page through it, and stop at the time budget."""

import pytest

import ckan.plugins.toolkit as tk

import ckanext.sse.action as sse_action


def _activities(n):
    return [{"id": f"a{i}", "data": {"package": {"id": "p"}}} for i in range(n)]


@pytest.fixture
def stubbed(monkeypatch):
    seen = {"dash": [], "diffs": 0, "available": 5}

    def fake_get_action(name):
        if name == "dashboard_activity_list":
            def dash(context, data_dict):
                seen["dash"].append(dict(data_dict))
                return _activities(min(seen["available"], data_dict["limit"]))
            return dash
        if name == "activity_diff":
            def diff(context, data_dict):
                seen["diffs"] += 1
                raise RuntimeError("no diff in this test")
            return diff
        raise AssertionError(name)

    monkeypatch.setattr(tk, "get_action", fake_get_action)
    return seen


def test_default_window_is_bounded(stubbed):
    sse_action.resource_activity_list({}, {})
    assert stubbed["dash"][0]["limit"] == sse_action.DEFAULT_ACTIVITY_SCAN_LIMIT
    assert stubbed["dash"][0]["offset"] == 0


def test_window_is_capped(stubbed):
    sse_action.resource_activity_list({}, {"limit": 100000})
    assert stubbed["dash"][0]["limit"] == sse_action.MAX_ACTIVITY_SCAN_LIMIT


def test_page_passes_offset_and_reports_next_offset(stubbed):
    stubbed["available"] = 1000
    result = sse_action.resource_activity_page({}, {"offset": 50, "limit": 20})
    assert stubbed["dash"][0] == {"limit": 20, "offset": 50}
    assert result["next_offset"] == 70


def test_last_window_has_no_next_offset(stubbed):
    stubbed["available"] = 5
    result = sse_action.resource_activity_page({}, {"offset": 100, "limit": 20})
    assert result["next_offset"] is None


def test_time_budget_stops_early_but_still_progresses(stubbed, monkeypatch):
    monkeypatch.setattr(sse_action, "ACTIVITY_DIFF_TIME_BUDGET_SECONDS", -1)
    stubbed["available"] = 5
    result = sse_action.resource_activity_page({}, {"limit": 5})
    assert stubbed["diffs"] == 1          # one activity always processed
    assert result["next_offset"] == 1     # resume where it stopped
