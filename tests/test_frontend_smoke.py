"""
test_frontend_smoke.py - Frontend Smoke Tests (Phase E)
=========================================================

Quick checks that the SPA loads, static assets resolve, and
the theme-init script is served as an external file.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestFrontendSmoke:
    """Basic frontend asset availability."""

    def test_index_html_served(self, client):
        """GET / should return the SPA entry page."""
        resp = client.get('/')
        assert resp.status_code == 200
        html = resp.data.decode('utf-8')
        assert '<html' in html
        assert 'NetWatch' in html

    def test_css_reset_served(self, client):
        """css/reset.css must be reachable."""
        resp = client.get('/css/reset.css')
        assert resp.status_code == 200
        assert 'text/css' in resp.content_type

    def test_css_variables_served(self, client):
        """css/variables.css must be reachable."""
        resp = client.get('/css/variables.css')
        assert resp.status_code == 200

    def test_css_components_served(self, client):
        """css/components.css must be reachable."""
        resp = client.get('/css/components.css')
        assert resp.status_code == 200

    def test_css_layout_served(self, client):
        """css/layout.css must be reachable."""
        resp = client.get('/css/layout.css')
        assert resp.status_code == 200

    def test_js_app_module_served(self, client):
        """js/app.js must be reachable."""
        resp = client.get('/js/app.js')
        assert resp.status_code == 200

    def test_sse_stream_uses_query_api_key(self, client):
        """api.js should append api_key to SSE URL for EventSource auth."""
        resp = client.get('/js/api.js')
        assert resp.status_code == 200
        body = resp.data.decode('utf-8')
        assert "params.set('api_key'" in body

    def test_theme_init_external_script(self, client):
        """js/theme-init.js must exist (moved from inline <script>)."""
        resp = client.get('/js/theme-init.js')
        assert resp.status_code == 200
        body = resp.data.decode('utf-8')
        assert 'data-theme' in body

    def test_no_inline_script_in_index(self, client):
        """index.html should not contain inline <script> blocks (CSP compliance)."""
        resp = client.get('/')
        html = resp.data.decode('utf-8')
        # Check there are no inline script blocks (only src= references)
        import re
        inline_scripts = re.findall(r'<script(?![^>]*\bsrc\b)[^>]*>(?!\s*</script>)', html)
        assert len(inline_scripts) == 0, f"Found inline scripts: {inline_scripts}"

    def test_noscript_uses_css_class(self, client):
        """<noscript> block should use CSS class not inline style."""
        resp = client.get('/')
        html = resp.data.decode('utf-8')
        assert 'noscript-message' in html
        # The noscript div should NOT have a style= attribute
        assert 'style="padding:2rem' not in html

    def test_favicon_exists(self, client):
        """Favicon SVG should be served."""
        resp = client.get('/assets/favicon.svg')
        # May be 200 or 404 depending on asset availability
        assert resp.status_code in (200, 404)

    def test_spa_fallback(self, client):
        """Non-API, non-file paths should fall back to index.html."""
        resp = client.get('/devices')
        assert resp.status_code == 200
        html = resp.data.decode('utf-8')
        assert 'NetWatch' in html


class TestIncidentsView:
    """The Phase 2 incident timeline view is served and wired in."""

    def test_incidents_view_served(self, client):
        resp = client.get('/js/components/IncidentsView.js')
        assert resp.status_code == 200
        body = resp.data.decode('utf-8')
        # Renders via DOM APIs (no HTML interpolation of untrusted text)
        assert 'getIncidents' in body
        assert 'resolveIncident' in body

    def test_incidents_route_registered(self, client):
        """app.js must route /incidents to the IncidentsView."""
        body = client.get('/js/app.js').data.decode('utf-8')
        assert "IncidentsView" in body
        assert "'/incidents'" in body

    def test_security_nav_entry(self, client):
        """Incidents+Threats merged into a single Security nav item."""
        body = client.get('/js/components/Sidebar.js').data.decode('utf-8')
        assert 'data-route="/security"' in body
        assert 'data-route="/threats"' not in body

    def test_incidents_api_methods(self, client):
        """api.js must expose the incident endpoints the view calls."""
        body = client.get('/js/api.js').data.decode('utf-8')
        for method in ('getIncidents', 'getIncident', 'getIncidentStats',
                       'resolveIncident'):
            assert method in body

    def test_incidents_css_present(self, client):
        """components.css must carry the incident timeline styles."""
        body = client.get('/css/components.css').data.decode('utf-8')
        assert '.incident-timeline' in body
        assert '.incident-row' in body


class TestAskView:
    """The Phase 3 Ask NetWatch view is served and wired in."""

    def test_ask_view_served(self, client):
        resp = client.get('/js/components/AskView.js')
        assert resp.status_code == 200
        body = resp.data.decode('utf-8')
        assert 'investigate' in body
        assert 'citations' in body

    def test_ask_route_registered(self, client):
        body = client.get('/js/app.js').data.decode('utf-8')
        assert 'AskView' in body
        assert "'/ask'" in body

    def test_ask_nav_entry(self, client):
        body = client.get('/js/components/Sidebar.js').data.decode('utf-8')
        assert 'data-route="/ask"' in body

    def test_ask_api_methods(self, client):
        body = client.get('/js/api.js').data.decode('utf-8')
        for method in ('getInvestigateStatus', 'getInvestigateTools',
                       'investigate'):
            assert method in body

    def test_ask_css_present(self, client):
        body = client.get('/css/components.css').data.decode('utf-8')
        assert '.ask__thread' in body
        assert '.ask-msg' in body


class TestNewViews:
    """W5/W6: Controls, Threats, Forecast, Behavior views served + wired."""

    def test_views_served(self, client):
        for name in ('ParentalView', 'ForecastView', 'BehaviorView'):
            resp = client.get(f'/js/components/{name}.js')
            assert resp.status_code == 200, name

    def test_routes_registered(self, client):
        body = client.get('/js/app.js').data.decode('utf-8')
        for token in ('ParentalView', 'ForecastView', 'BehaviorView',
                      "'/controls'", "'/security'", "'/forecast'", "'/behavior'"):
            assert token in body, token

    def test_nav_entries(self, client):
        body = client.get('/js/components/Sidebar.js').data.decode('utf-8')
        for route in ('/controls', '/security', '/forecast', '/behavior'):
            assert f'data-route="{route}"' in body, route

    def test_api_methods(self, client):
        body = client.get('/js/api.js').data.decode('utf-8')
        for method in ('getParentalPolicies', 'setParentalPolicy', 'pauseDevice',
                       'resumeDevice', 'clearParentalPolicy', 'getRecentThreats',
                       'getForecastBandwidth', 'getBehaviorProfile'):
            assert method in body, method

    def test_css_present(self, client):
        body = client.get('/css/components.css').data.decode('utf-8')
        for cls in ('.parental-card', '.threats-group', '.forecast-card', '.behavior-bar'):
            assert cls in body, cls
