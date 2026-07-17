"""
test_app_catalog.py - Domain → friendly app/site/org (visibility polish)
=========================================================================
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intelligence.app_catalog import classify_site, registered_domain, app_and_org


class TestRegisteredDomain:
    def test_basic(self):
        assert registered_domain("graph.instagram.com") == "instagram.com"
        assert registered_domain("i-fallback.instagram.com") == "instagram.com"
        assert registered_domain("example.com") == "example.com"

    def test_two_label_tld(self):
        assert registered_domain("shop.amazon.co.uk") == "amazon.co.uk"


class TestClassifySite:
    def test_known_apps_and_org(self):
        # The exact case from the field test: i.instagram.com should read Meta.
        s = classify_site("i.instagram.com")
        assert s["app"] == "Instagram"
        assert s["org"] == "Meta"

    def test_youtube_via_googlevideo(self):
        s = classify_site("rr4---sn-x.googlevideo.com")
        assert s["app"] == "YouTube"
        assert s["org"] == "Google"

    def test_facebook_and_whatsapp_are_meta(self):
        assert classify_site("graph.facebook.com")["org"] == "Meta"
        assert classify_site("g.whatsapp.net")["app"] == "WhatsApp"

    def test_unknown_domain_keeps_domain_no_app(self):
        s = classify_site("random.example.org")
        assert s["domain"] == "example.org"
        assert s["app"] is None and s["org"] is None

    def test_app_and_org_helper(self):
        assert app_and_org("youtu.be") == ("YouTube", "Google")
        assert app_and_org("nowhere.invalid") == (None, None)

    def test_carrier_infra_labelled(self):
        s = classify_site("epdg.epc.mnc086.mcc404.pub.3gppnetwork.org")
        assert s["org"] == "Mobile carrier"
