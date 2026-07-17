"""
app_catalog.py - Domain → friendly app / site / owning-org (visibility polish)
==============================================================================

The Activity feed shows raw lookups like ``graph.instagram.com``,
``i-fallback.instagram.com``, ``footprints-pa.googleapis.com`` — accurate but
unreadable for a non-technical user. This maps a hostname to (a) the
**registered domain** (so subdomains collapse into one entry) and (b) a
friendly **app name** + **owning org** when it's a known consumer service.

Domain-based, so it works whenever we have ANY name for the flow — a plain
DNS lookup, a TLS/QUIC SNI — i.e. it also answers "show me the app even with
DNS on", not just the IP→org fallback. Pure + deterministic.
"""

from typing import Optional

# registered-domain → (friendly app/site name, owning org)
_APP_MAP = {
    "instagram.com": ("Instagram", "Meta"),
    "cdninstagram.com": ("Instagram", "Meta"),
    "facebook.com": ("Facebook", "Meta"),
    "fbcdn.net": ("Facebook", "Meta"),
    "fb.com": ("Facebook", "Meta"),
    "whatsapp.com": ("WhatsApp", "Meta"),
    "whatsapp.net": ("WhatsApp", "Meta"),
    "messenger.com": ("Messenger", "Meta"),
    "youtube.com": ("YouTube", "Google"),
    "googlevideo.com": ("YouTube", "Google"),
    "ytimg.com": ("YouTube", "Google"),
    "youtu.be": ("YouTube", "Google"),
    "google.com": ("Google", "Google"),
    "googleapis.com": ("Google", "Google"),
    "gstatic.com": ("Google", "Google"),
    "googleusercontent.com": ("Google", "Google"),
    "google-analytics.com": ("Google", "Google"),
    "netflix.com": ("Netflix", "Netflix"),
    "nflxvideo.net": ("Netflix", "Netflix"),
    "nflximg.net": ("Netflix", "Netflix"),
    "tiktok.com": ("TikTok", "ByteDance"),
    "tiktokcdn.com": ("TikTok", "ByteDance"),
    "byteoversea.com": ("TikTok", "ByteDance"),
    "twitter.com": ("X (Twitter)", "X"),
    "x.com": ("X (Twitter)", "X"),
    "twimg.com": ("X (Twitter)", "X"),
    "snapchat.com": ("Snapchat", "Snap"),
    "sc-cdn.net": ("Snapchat", "Snap"),
    "spotify.com": ("Spotify", "Spotify"),
    "scdn.co": ("Spotify", "Spotify"),
    "reddit.com": ("Reddit", "Reddit"),
    "redd.it": ("Reddit", "Reddit"),
    "linkedin.com": ("LinkedIn", "Microsoft"),
    "discord.com": ("Discord", "Discord"),
    "discordapp.com": ("Discord", "Discord"),
    "discord.gg": ("Discord", "Discord"),
    "twitch.tv": ("Twitch", "Amazon"),
    "pinterest.com": ("Pinterest", "Pinterest"),
    "microsoft.com": ("Microsoft", "Microsoft"),
    "windows.com": ("Microsoft", "Microsoft"),
    "windowsupdate.com": ("Windows Update", "Microsoft"),
    "live.com": ("Microsoft", "Microsoft"),
    "office.com": ("Microsoft Office", "Microsoft"),
    "msftconnecttest.com": ("Windows (connectivity)", "Microsoft"),
    "apple.com": ("Apple", "Apple"),
    "icloud.com": ("iCloud", "Apple"),
    "mzstatic.com": ("Apple", "Apple"),
    "amazon.com": ("Amazon", "Amazon"),
    "amazonaws.com": ("Amazon (AWS)", "Amazon"),
    "media-amazon.com": ("Amazon", "Amazon"),
    "github.com": ("GitHub", "Microsoft"),
    "cloudflare.com": ("Cloudflare", "Cloudflare"),
    "adguard.com": ("AdGuard DNS", "AdGuard"),
    "gvt1.com": ("Google", "Google"),
    "gvt2.com": ("Google", "Google"),
    "ggpht.com": ("YouTube", "Google"),
    # carrier / VoWiFi infra — legitimate, not an app
    "3gppnetwork.org": ("Carrier network (VoWiFi)", "Mobile carrier"),
}

# Two-label public suffixes we must not collapse to (so "site.co.uk" keeps
# three labels). Small, common set — enough for the display heuristic.
_TWO_LABEL_TLDS = {
    "co.uk", "com.au", "co.in", "co.jp", "com.br", "co.nz", "org.uk",
    "ac.uk", "gov.uk", "com.tr", "co.za", "com.mx",
}


def registered_domain(qname: str) -> str:
    """eTLD+1 for display: 'a.b.instagram.com' → 'instagram.com', handling a
    small set of two-label TLDs ('x.co.uk' → 'x.co.uk')."""
    labels = [l for l in (qname or "").lower().rstrip(".").split(".") if l]
    if len(labels) < 2:
        return qname.lower().rstrip(".")
    last2 = ".".join(labels[-2:])
    if last2 in _TWO_LABEL_TLDS and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last2


def classify_site(qname: str) -> dict:
    """Return {'domain', 'app', 'org'} for a hostname. app/org are None when
    it's not a known consumer service (domain is always set)."""
    q = (qname or "").lower().rstrip(".")
    if not q:
        return {"domain": "", "app": None, "org": None}
    for dom, (app, org) in _APP_MAP.items():
        if q == dom or q.endswith("." + dom):
            return {"domain": dom, "app": app, "org": org}
    return {"domain": registered_domain(q), "app": None, "org": None}


def app_and_org(qname: str):
    """Convenience: (app, org) or (None, None)."""
    s = classify_site(qname)
    return s["app"], s["org"]
