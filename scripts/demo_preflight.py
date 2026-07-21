"""
demo_preflight.py - Check everything the demo depends on, before the demo
==========================================================================

Run this ten minutes before going on stage, not during. Every check is
read-only except ``--fix``, which only ever *releases* things (clears stale
blocks) — nothing here can cut a device off.

    venv/Scripts/python.exe scripts/demo_preflight.py
    venv/Scripts/python.exe scripts/demo_preflight.py --fix

Exit code is 0 when everything a live demo needs is ready, 1 otherwise, so it
can also be used as a smoke check in CI.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

OK, WARN, FAIL = "PASS", "WARN", "FAIL"

_results = []


def check(name, status, detail=""):
    _results.append((name, status, detail))
    icon = {OK: "[ok]  ", WARN: "[warn]", FAIL: "[FAIL]"}[status]
    print(f"{icon} {name}" + (f"\n         {detail}" if detail else ""))


# --------------------------------------------------------------------------- #

def check_admin():
    """Packet capture needs raw sockets; without this nothing else matters."""
    try:
        import ctypes
        elevated = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        elevated = os.geteuid() == 0 if hasattr(os, "geteuid") else False
    check("Running elevated (required for capture + WinDivert)",
          OK if elevated else FAIL,
          "" if elevated else "Re-run the terminal as Administrator.")


def check_hotspot():
    """The demo is hotspot-based: the ICS adapter must actually be up."""
    from packet_capture.mode_detector import ModeDetector
    d = ModeDetector()
    d._all_interfaces = d._enumerate_interfaces()
    iface = d._pick_hotspot_interface()
    if iface:
        check("Hotspot adapter present", OK,
              f"{iface.name} at {iface.ip_address}")
    else:
        check("Hotspot adapter present", FAIL,
              "Turn on Windows Mobile Hotspot (Settings > Network > "
              "Mobile hotspot) before starting NetWatch.")


def check_npcap():
    try:
        from scapy.arch.windows import get_windows_if_list  # noqa: F401
        import scapy.all as scapy
        ok = bool(getattr(scapy.conf, "use_pcap", True))
        check("Npcap / libpcap available", OK if ok else FAIL,
              "" if ok else "Install Npcap with WinPcap API-compatible mode.")
    except Exception as exc:
        check("Npcap / libpcap available", FAIL, str(exc))


def check_windivert():
    """The only rung that stops DoH/QUIC apps."""
    try:
        import pydivert  # noqa: F401
        check("pydivert (packet-level blocking) importable", OK)
    except Exception:
        check("pydivert (packet-level blocking) importable", WARN,
              "Blocking will fall back to DNS sinkholing, which Instagram "
              "and YouTube bypass. pip install pydivert")


def check_llm():
    """Both AI features degrade gracefully, but the demo is better with a model."""
    from intelligence.llm_runtime import get_runtime
    rt = get_runtime()
    if rt is None:
        check("Local model (Ollama) reachable", WARN,
              "AI features will use their deterministic paths. Start it with "
              "'ollama serve' and confirm 'ollama list' shows llama3.2:3b.")
        return
    # A cloud-routed model would break the zero-cloud claim — say so loudly.
    check("Local model (Ollama) reachable", OK, f"model={rt.model}")
    if "cloud" in str(rt.model).lower():
        check("Model is local (zero-cloud claim holds)", FAIL,
              f"'{rt.model}' routes to a remote host. Set "
              "NETWATCH_LLM_MODEL=llama3.2:3b")
    else:
        check("Model is local (zero-cloud claim holds)", OK)


def check_stale_blocks(fix=False):
    """A pause left over from rehearsal will silently blackhole a device."""
    from database.queries.policy_queries import get_policies, upsert_policy
    policies = get_policies() or []
    active = [p for p in policies if p.get("paused")]
    if not active:
        check("No devices left blocked from a previous run", OK,
              f"{len(policies)} policy row(s), none paused")
        return
    macs = ", ".join(p.get("device_mac", "?") for p in active)
    if fix:
        for p in active:
            upsert_policy(p["device_mac"], paused=False)
        check("No devices left blocked from a previous run", OK,
              f"released: {macs}")
    else:
        check("No devices left blocked from a previous run", FAIL,
              f"still paused: {macs}  (re-run with --fix to release)")


def check_blocking_rules():
    from database.queries.blocking_queries import get_rules
    rules = [r for r in (get_rules() or []) if r.get("enabled")]
    if not rules:
        check("Blocking rules", OK, "none active")
        return
    desc = ", ".join(f"{r['domain']}({r.get('scope')})" for r in rules[:5])
    check("Blocking rules", WARN,
          f"{len(rules)} active from a previous run: {desc}")


def check_db():
    """Schema must carry the columns the new enforcement paths need."""
    from database.connection import get_connection
    try:
        with get_connection() as conn:
            cur = conn.cursor()
            cur.execute("PRAGMA table_info(blocking_rules)")
            rule_cols = {r[1] for r in cur.fetchall()}
            cur.execute("PRAGMA table_info(device_policies)")
            pol_cols = {r[1] for r in cur.fetchall()}
        missing = []
        if "scope" not in rule_cols:
            missing.append("blocking_rules.scope")
        if "pause_expires_at" not in pol_cols:
            missing.append("device_policies.pause_expires_at")
        check("Database schema up to date (migrations 016/017)",
              OK if not missing else FAIL,
              "" if not missing else f"missing: {', '.join(missing)} — start "
              "NetWatch once to run migrations")
    except Exception as exc:
        check("Database schema up to date (migrations 016/017)", FAIL, str(exc))


def check_ai_paths():
    """Both AI features must produce something even with no model at all."""
    from intelligence.responder import Responder
    from intelligence.briefing import Briefer, compose_fallback, gather_facts

    inc = {"id": 0, "severity": "critical", "device_mac": "aa:bb:cc:dd:ee:01",
           "alerts": [{"message": "test",
                       "details": {"threat_type": "port_scan",
                                   "confidence": 0.95,
                                   "evidence": [{"signal": "vertical_scan"}]}}]}
    v = Responder(runtime=None).assess(inc)
    check("AI responder works with no model",
          OK if v.get("recommended_action") == "quarantine" else FAIL,
          f"verdict={v.get('recommended_action')} (deterministic path)")

    text = compose_fallback(gather_facts(10))
    check("AI briefing works with no model", OK if text else FAIL,
          text[:100] if text else "")


def main():
    parser = argparse.ArgumentParser(description="NetWatch demo pre-flight")
    parser.add_argument("--fix", action="store_true",
                        help="Release stale blocks (only ever unblocks)")
    args = parser.parse_args()

    print("\nNetWatch demo pre-flight\n" + "=" * 60)
    check_admin()
    check_npcap()
    check_hotspot()
    check_windivert()
    check_db()
    check_stale_blocks(fix=args.fix)
    check_blocking_rules()
    check_llm()
    check_ai_paths()

    failures = [r for r in _results if r[1] == FAIL]
    warnings = [r for r in _results if r[1] == WARN]
    print("=" * 60)
    print(f"{len(_results)} checks: {len(_results) - len(failures) - len(warnings)} pass, "
          f"{len(warnings)} warn, {len(failures)} fail")
    if failures:
        print("\nNOT READY — fix these first:")
        for name, _s, detail in failures:
            print(f"  - {name}: {detail}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
