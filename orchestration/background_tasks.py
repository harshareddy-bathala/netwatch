"""
orchestration/background_tasks.py - Background Task Management
================================================================

Cleanup scheduler, anomaly detector, health monitor, and thread watchdog.
All tasks run as daemon threads and respect ``state.shutdown_event``.
"""

import logging
import threading
import time
from datetime import datetime, timedelta

from orchestration import state

logger = logging.getLogger(__name__)


# =========================================================================
# Anomaly detector
# =========================================================================

def start_anomaly_detector(alert_engine):
    """Start ML anomaly detector in background thread."""
    from alerts.anomaly_detector import AnomalyDetector

    def _capture_alive() -> bool:
        engine = state.capture_engine
        try:
            return engine is not None and engine.is_running()
        except Exception:
            return False

    try:
        state.detector = AnomalyDetector(
            alert_engine=alert_engine,
            shutdown_event=state.shutdown_event,
            capture_alive_fn=_capture_alive,
        )

        state.detector_thread = threading.Thread(
            target=state.detector.run,
            daemon=True,
            name="AnomalyDetector"
        )
        state.detector_thread.start()
        return True
    except Exception as e:
        logger.error("Failed to start anomaly detector: %s", e)
        return False


# =========================================================================
# Flow normalizer (Phase 0, AI-first substrate)
# =========================================================================

def start_flow_normalizer():
    """Start the packet-batch → flow/DNS telemetry consumer.

    Subscribes to the in-process event bus; never touches the capture
    hot path.  See intelligence/flow_normalizer.py and ROADMAP.md P0.6.
    """
    from intelligence.flow_normalizer import FlowNormalizer

    try:
        state.flow_normalizer = FlowNormalizer(
            shutdown_event=state.shutdown_event,
        )
        return state.flow_normalizer.start()
    except Exception as e:
        logger.error("Failed to start flow normalizer: %s", e)
        return False


# =========================================================================
# Digital twin + behavior learning (Phase 1, AI-first)
# =========================================================================

def start_twin_builder():
    """Start the digital-twin graph builder (event-bus consumer)."""
    from intelligence.twin import TwinBuilder

    try:
        state.twin_builder = TwinBuilder(
            shutdown_event=state.shutdown_event,
        )
        return state.twin_builder.start()
    except Exception as e:
        logger.error("Failed to start twin builder: %s", e)
        return False


def start_behavior_analyzer(alert_engine):
    """Start per-device behavior learning (event-bus consumer)."""
    from intelligence.behavior import BehaviorAnalyzer

    try:
        state.behavior_analyzer = BehaviorAnalyzer(
            alert_engine=alert_engine,
            shutdown_event=state.shutdown_event,
        )
        return state.behavior_analyzer.start()
    except Exception as e:
        logger.error("Failed to start behavior analyzer: %s", e)
        return False


def start_threat_detector(alert_engine):
    """Start the Phase 2 threat detector pack (event-bus consumer)."""
    from intelligence.threats import ThreatDetector

    try:
        state.threat_detector = ThreatDetector(
            alert_engine=alert_engine,
            shutdown_event=state.shutdown_event,
        )
        return state.threat_detector.start()
    except Exception as e:
        logger.error("Failed to start threat detector: %s", e)
        return False


def start_vpn_detector(alert_engine):
    """Start VPN/encrypted-tunnel detection (event-bus consumer, W3)."""
    from intelligence.vpn_detector import VpnDetector

    try:
        state.vpn_detector = VpnDetector(
            alert_engine=alert_engine,
            shutdown_event=state.shutdown_event,
        )
        return state.vpn_detector.start()
    except Exception as e:
        logger.error("Failed to start VPN detector: %s", e)
        return False


# Shared domain→IP resolver cache. Used by both the periodic policy sweep and
# the immediate apply below, so a rule added from the UI reuses (and warms) the
# same cache the enforcer reads.
_domain_blocklist = None
_domain_blocklist_lock = threading.Lock()


def _get_domain_blocklist():
    global _domain_blocklist
    with _domain_blocklist_lock:
        if _domain_blocklist is None:
            from packet_capture.domain_blocklist import DomainBlocklist
            _domain_blocklist = DomainBlocklist()
        return _domain_blocklist


def _mac_ip_map(macs) -> dict:
    """Resolve MACs → their *current* IPs for packet-level blocking.

    Bounded by ``last_seen``: a lease is only usable while the device that
    holds it is still around. Without the bound we would enforce against
    whatever address the device had days ago — and DHCP hands those out again,
    so the block would land on an innocent device that inherited the IP.
    """
    if not macs:
        return {}
    try:
        from database.connection import get_connection
        from config import HOTSPOT_STALE_DEVICE_SECONDS
        out = {}
        with get_connection() as conn:
            cur = conn.cursor()
            ph = ",".join("?" for _ in macs)
            cur.execute(
                f"""SELECT LOWER(mac_address),
                           COALESCE(ipv4_address, ip_address) AS ip
                    FROM devices
                    WHERE LOWER(mac_address) IN ({ph})
                      AND last_seen >= datetime('now', ?)""",
                (*(m.lower() for m in macs),
                 f"-{max(60, int(HOTSPOT_STALE_DEVICE_SECONDS))} seconds"),
            )
            for mac, ip in cur.fetchall():
                if ip:
                    out[mac] = ip
        return out
    except Exception:
        return {}


def _macs_to_ips(macs) -> set:
    """Blocked MACs → the set of their current IPs."""
    return set(_mac_ip_map(macs).values())


def _resolve_domain_targets(blocklist=None):
    """Resolve enabled domain rules → (pairs, network_wide_server_ips).

    DNS sinkholing alone does not block a phone that uses DoH or reconnects
    over QUIC to a cached IP (observed: blocking instagram.com left the app
    working). Dropping the domain's server IPs at the packet level does.

    The split is what keeps that from being collateral. A rule naming a device
    yields ``(client_ip, server_ip)`` pairs, so only that client's conversation
    dies; a rule with no device — or one explicitly scoped 'network' — yields
    bare server IPs that drop for everyone, this host included. Previously
    every rule produced the second kind, which is why blocking a site for one
    phone also cut it off for the laptop running NetWatch.
    """
    pairs, network_ips = set(), set()
    blocklist = blocklist or _get_domain_blocklist()
    try:
        from database.queries.blocking_queries import get_rules
        from packet_capture.sni_ip_learner import sni_ip_learner

        rules = [r for r in (get_rules() or [])
                 if r.get('enabled') and r.get('domain')]
        if not rules:
            sni_ip_learner.set_blocked_domains(set())
            return pairs, network_ips

        # Watch the whole app family on the wire, so the SNI learner picks up
        # CDN hosts (scontent.cdninstagram.com) our own resolver never sees —
        # that is what actually stops the app.
        all_domains = {r['domain'] for r in rules}
        sni_ip_learner.set_blocked_domains(blocklist.expand(all_domains))

        # One lookup for every device named by a rule, recency-bounded.
        rule_macs = {(r.get('device_mac') or '').lower()
                     for r in rules if r.get('device_mac')}
        mac_ips = _mac_ip_map(rule_macs) if rule_macs else {}

        for rule in rules:
            domain = rule['domain']
            family = blocklist.expand({domain})
            # Resolved IPs (immediate, approximate) + observed IPs (accurate,
            # learned from this family's real connections).
            servers = (blocklist.ips_for({domain})
                       | sni_ip_learner.learned_ips(family))
            if not servers:
                continue

            mac = (rule.get('device_mac') or '').lower()
            scope = (rule.get('scope') or '').lower()
            if mac and scope != 'network':
                client_ip = mac_ips.get(mac)
                if not client_ip:
                    # Device not currently present — nothing to enforce
                    # against, and guessing an address would block someone
                    # else. The DNS sinkhole still covers it if it returns.
                    continue
                pairs.update((client_ip, s) for s in servers)
            else:
                network_ips |= servers
    except Exception as exc:
        logger.debug("domain blocklist resolve failed: %s", exc)
    return pairs, network_ips


def apply_blocking_rules_now() -> dict:
    """Re-resolve enabled domain rules and push them to the packet blocker
    immediately, instead of waiting up to a full policy-sweep interval.

    Called on every blocking-rule mutation so "Block" visibly takes effect at
    once — a 30s delay reads as "blocking is broken". Returns a small status
    dict for the API to surface. Never raises.
    """
    from orchestration import state
    traffic = getattr(state, 'traffic_blocker', None)
    if traffic is None:
        return {"applied": False, "reason": "packet blocker not running"}
    try:
        pairs, network_ips = _resolve_domain_targets()

        # Preserve device-level blocks (pause/quota) already enforced, so
        # applying a domain rule never accidentally un-pauses a device. Those
        # live in their own bucket now, so this is a plain read-back rather
        # than the old subtract-the-domain-IPs guesswork.
        device_ips = set(traffic.get_status().get("blocked_ips") or [])

        traffic.set_policy(device_ips=device_ips, pairs=pairs,
                           server_ips=network_ips)
        return {"applied": True,
                "device_scoped_pairs": len(pairs),
                "network_wide_ips": len(network_ips),
                "mode": traffic.get_status().get("mode")}
    except Exception as exc:
        logger.warning("Immediate blocking-rule apply failed: %s", exc)
        return {"applied": False, "reason": str(exc)}


def start_policy_enforcer(interval: int = 5):
    # 5s, not 30s: the SNI learner discovers a blocked app's real CDN addresses
    # continuously, and each one only takes effect on the next sweep. A 30s
    # sweep left the app working for half a minute after it was "blocked".
    # The sweep is cheap — small indexed queries plus a TTL-cached resolve.
    """Evaluate device policies (parental controls / quotas, W5) and push
    the currently-blocked set to both blockers. Daemon thread; cheap.

    Resolution helpers live at module level so the immediate-apply path
    (``apply_blocking_rules_now``) uses exactly the same logic as the
    sweep — the two drifting apart is how "Block" behaved differently
    depending on whether you had waited for a sweep.
    """

    def _loop():
        from database.queries.policy_queries import (
            get_policies, get_usage_today_by_mac, evaluate_blocked_macs,
        )
        blocklist = _get_domain_blocklist()
        logger.info("Policy enforcer started (device quotas / schedules / pause "
                    "/ domain blocking)")
        while not state.shutdown_event.wait(timeout=interval):
            try:
                policies = get_policies()
                dns = getattr(state, 'dns_blocker', None)
                traffic = getattr(state, 'traffic_blocker', None)

                # Domain rules are enforced whether or not any device policy
                # exists — they are independent features.
                pairs, network_ips = (
                    _resolve_domain_targets(blocklist) if traffic else (set(), set())
                )

                # Device-level blocks: pause / quota / bedtime. These are
                # whole-device by intent, unlike domain rules.
                device_ips = set()
                if policies:
                    usage = get_usage_today_by_mac()
                    blocked = evaluate_blocked_macs(policies, usage)
                    macs = set(blocked.keys())
                    device_ips = _macs_to_ips(macs)
                else:
                    macs = set()

                # DNS sinkhole (fast, name-level) + real packet drop.
                if dns:
                    dns.set_blocked_macs(macs)
                if traffic:
                    traffic.set_policy(device_ips=device_ips, pairs=pairs,
                                       server_ips=network_ips)
                    # Apply any widening the blocker deferred to protect the
                    # kernel handle from per-sweep churn.
                    traffic.flush_pending()
            except Exception as e:
                logger.debug("Policy enforcer error: %s", e)

    t = threading.Thread(target=_loop, name="PolicyEnforcer", daemon=True)
    t.start()
    state.policy_enforcer_thread = t
    return True


def start_traffic_blocker():
    """Start the WinDivert/ARP packet-level enforcer (parental controls)."""
    from packet_capture.traffic_blocker import TrafficBlocker
    try:
        state.traffic_blocker = TrafficBlocker()
        logger.info("Traffic blocker ready (%s)", state.traffic_blocker.get_status()["mode"])
        return True
    except Exception as e:
        logger.error("Failed to start traffic blocker: %s", e)
        return False


# =========================================================================
# Health monitor
# =========================================================================

def start_health_monitor(alert_engine):
    """Start system health monitoring in background thread."""
    from utils.health_monitor import HealthMonitor

    try:
        state.health_monitor = HealthMonitor(
            check_interval=60,
            alert_engine=alert_engine,
        )
        state.health_monitor.start()
        return True
    except Exception as e:
        logger.error("Failed to start health monitor: %s", e)
        return False


# =========================================================================
# Cleanup task
# =========================================================================

def start_cleanup_task():
    """Start periodic cleanup task for 24/7 operation.

    Phase 3 enhancements:
    * Uses adaptive_cleanup() which adjusts retention based on DB size
    * WAL checkpoint after each cleanup cycle
    * Stale device pruning from in-memory state every 5 minutes
    """
    from database.rollup import rollup_traffic, cleanup_old_rollups
    from database.queries.maintenance import (
        run_full_cleanup, adaptive_cleanup, run_wal_checkpoint,
    )

    def cleanup_loop():
        from database.queries.maintenance import get_database_size_mb

        last_cleanup = datetime.now()
        last_full_cleanup_date = None
        last_device_prune = time.time()
        last_wal_check = time.time()

        while not state.shutdown_event.is_set():
            try:
                now = datetime.now()
                now_ts = time.time()

                # Every 5 minutes: prune stale devices from memory (Phase 3)
                try:
                    from config import STALE_DEVICE_PRUNE_INTERVAL, STALE_DEVICE_TIMEOUT_HOURS
                except ImportError:
                    STALE_DEVICE_PRUNE_INTERVAL = 300
                    STALE_DEVICE_TIMEOUT_HOURS = 2

                if now_ts - last_device_prune >= STALE_DEVICE_PRUNE_INTERVAL:
                    try:
                        from utils.realtime_state import dashboard_state
                        dashboard_state.prune_stale_devices(
                            stale_hours=STALE_DEVICE_TIMEOUT_HOURS
                        )
                    except Exception as e:
                        logger.error("Stale device prune error: %s", e)
                    last_device_prune = now_ts

                # Every 60 minutes: check WAL size and checkpoint if large
                if now_ts - last_wal_check >= 3600:
                    try:
                        from database.queries.maintenance import get_wal_size_mb
                        wal_mb = get_wal_size_mb()
                        if wal_mb > 100:
                            logger.warning(
                                "WAL file is %.1f MB — running TRUNCATE checkpoint",
                                wal_mb,
                            )
                            run_wal_checkpoint("TRUNCATE")
                        elif wal_mb > 50:
                            run_wal_checkpoint("PASSIVE")
                    except Exception as e:
                        logger.error("WAL size check error: %s", e)
                    last_wal_check = now_ts

                # Every 15 minutes: rollup traffic data + adaptive cleanup
                if now - last_cleanup >= timedelta(minutes=15):
                    try:
                        result = rollup_traffic(raw_retention_hours=24)
                        if result["deleted"] > 0:
                            logger.info("Traffic rollup: %d raw rows archived", result["deleted"])
                    except Exception as e:
                        logger.error("Traffic rollup error: %s", e)

                    try:
                        cleanup_old_rollups(days_to_keep=90)
                    except Exception as e:
                        logger.error("Rollup cleanup error: %s", e)

                    # Phase 3: adaptive cleanup with WAL checkpoint
                    try:
                        result = adaptive_cleanup()
                        total_deleted = sum(v for k, v in result.items() if k.endswith('_deleted'))
                        if total_deleted > 0:
                            logger.info("Periodic cleanup: removed %s records, freed %.1f MB",
                                         f"{total_deleted:,}", result.get('freed_mb', 0))
                    except Exception as e:
                        logger.error("Periodic cleanup error: %s", e)

                    last_cleanup = now

                # Daily at 3 AM: full comprehensive cleanup
                if now.hour >= 3 and last_full_cleanup_date != now.date():
                    logger.info("Daily cleanup starting...")
                    try:
                        result = run_full_cleanup(
                            traffic_retention_days=7,
                            alert_retention_days=30,
                            stats_retention_days=30,
                            daily_usage_retention_days=90,
                        )
                        logger.info(
                            "Daily cleanup complete: deleted %s records, freed %.1f MB",
                            f"{sum(v for k, v in result.items() if k.endswith('_deleted')):,}",
                            result.get('freed_mb', 0),
                        )
                    except Exception as e:
                        logger.error("Daily cleanup error: %s", e)

                    # Always VACUUM daily to reclaim space
                    try:
                        from database.queries.maintenance import vacuum_database
                        vacuum_database()
                    except Exception as e:
                        logger.error("Daily VACUUM error: %s", e)

                    # Phase 3: TRUNCATE checkpoint daily to fully reclaim WAL
                    try:
                        run_wal_checkpoint("TRUNCATE")
                    except Exception as e:
                        logger.error("Daily WAL checkpoint error: %s", e)

                    last_full_cleanup_date = now.date()

                state.shutdown_event.wait(60)  # 60s base interval for responsive scheduling
            except Exception as e:
                logger.error("Cleanup task error: %s", e)
                state.shutdown_event.wait(60)

    state.cleanup_thread = threading.Thread(
        target=cleanup_loop,
        daemon=True,
        name="CleanupTask"
    )
    state.cleanup_thread.start()
    return True


# =========================================================================
# Thread watchdog
# =========================================================================

_WATCHED_THREAD_PATTERNS = {
    # Capture engine threads (Scapy capture + processor)
    "CaptureEngine": ("CaptureEngine-Capture", "CaptureEngine-Process"),
    # Background hostname resolver + mDNS browser
    "HostnameResolver": ("HostnameResolver-BG", "mDNS-Browse"),
    # Periodic tasks
    "DiscoveryTask": ("DiscoveryTask",),
    "CleanupTask": ("CleanupTask",),
    "AnomalyDetector": ("AnomalyDetector",),
    "HealthMonitor": ("HealthMonitor",),
    "FlowNormalizer": ("FlowNormalizer",),
    "TwinBuilder": ("TwinBuilder",),
    "BehaviorAnalyzer": ("BehaviorAnalyzer",),
}


def _thread_watchdog():
    """Periodically check that critical daemon threads are alive.

    Runs every 30s.  If a watched thread has disappeared, logs a
    warning so operators can detect silent crashes.  For safe-to-restart
    threads (CleanupTask), attempts auto-restart with cooldown.
    """
    # Restart tracking: label -> (restart_count, window_start_time)
    _restart_tracker: dict = {}
    _MAX_RESTARTS_PER_HOUR = 3

    # Restart handlers for threads that are safe to auto-restart.
    # CaptureEngine is excluded because it requires mode context.
    _restart_handlers = {
        "CleanupTask": start_cleanup_task,
    }

    start = time.time()
    while not state.shutdown_event.is_set():
        # Give threads a short grace period to start before warning
        if time.time() - start < 30:
            state.shutdown_event.wait(5)
            continue
        alive_names = {t.name for t in threading.enumerate() if t.is_alive()}
        for label, patterns in _WATCHED_THREAD_PATTERNS.items():
            present = any(
                any(name.startswith(pat) for pat in patterns)
                for name in alive_names
            )
            if not present:
                logger.warning(
                    "Thread watchdog: '%s' is not alive -- it may have crashed silently",
                    label,
                )
                # Attempt auto-restart for safe threads
                if label in _restart_handlers:
                    now_ts = time.time()
                    count, window_start = _restart_tracker.get(label, (0, now_ts))
                    # Reset counter if window expired
                    if now_ts - window_start > 3600:
                        count, window_start = 0, now_ts
                    if count < _MAX_RESTARTS_PER_HOUR:
                        logger.warning("Thread watchdog: attempting auto-restart of '%s'", label)
                        try:
                            _restart_handlers[label]()
                            _restart_tracker[label] = (count + 1, window_start)
                            logger.info("Thread watchdog: '%s' restarted successfully", label)
                        except Exception as e:
                            logger.error("Thread watchdog: failed to restart '%s': %s", label, e)
                    else:
                        logger.error(
                            "Thread watchdog: '%s' exceeded max restarts (%d/hr) -- not restarting",
                            label, _MAX_RESTARTS_PER_HOUR,
                        )
        state.shutdown_event.wait(30)


def start_thread_watchdog():
    """Start the thread watchdog in a daemon thread."""
    t = threading.Thread(target=_thread_watchdog, daemon=True, name="ThreadWatchdog")
    t.start()
    return True
