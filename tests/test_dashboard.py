"""Dashboard, navigation, and workflow placeholder pages."""

from __future__ import annotations


def test_dashboard_renders_entry_points_and_notice(app_client):
    response = app_client.get("/")
    assert response.status_code == 200
    body = response.text
    assert "PHANTOM" in body
    # PRD §10 navigation
    for label in ("Dashboard", "Website Check", "Code Review", "Log Analysis", "History", "Settings"):
        assert label in body
    # PRD FR-14: false-positive/negative disclaimer visible on the dashboard
    assert "advisory" in body.lower()
    assert "human verification" in body.lower()
    # Empty state before any analyses exist
    assert "No analyses yet" in body


def test_workflow_placeholders_show_notices(app_client):
    website = app_client.get("/website-check")
    assert website.status_code == 200
    assert "Authorization notice" in website.text
    assert "passive" in website.text.lower()

    code = app_client.get("/code-review")
    assert code.status_code == 200
    assert "Privacy notice" in code.text
    assert "never executed" in code.text.lower()

    logs = app_client.get("/log-analysis")
    assert logs.status_code == 200
    assert "indicators for review" in logs.text
    assert "not proof" in logs.text


def test_history_and_settings_render(app_client):
    history = app_client.get("/history")
    assert history.status_code == 200
    assert "Analysis history" in history.text

    settings_page = app_client.get("/settings")
    assert settings_page.status_code == 200
    assert "AI assistance" in settings_page.text
    assert "Disabled" in settings_page.text  # no provider configured by default


def test_unknown_page_renders_friendly_404(app_client):
    response = app_client.get("/definitely-not-a-page")
    assert response.status_code == 404
    assert "Page not found" in response.text
    # The requested path is never echoed back.
    assert "definitely-not-a-page" not in response.text


def test_report_route_is_reserved_until_phase_5(app_client):
    response = app_client.get("/analyses/1/report")
    assert response.status_code == 404
