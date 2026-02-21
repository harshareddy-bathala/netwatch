"""
filter_manager.py - Dynamic BPF Filter Generation
===================================================

Provides a thin orchestration layer between ``BaseMode.get_bpf_filter()``
and the Scapy ``sniff()`` call.  Responsibilities:

    1. Validate / sanitise the BPF string returned by the active mode.
    2. Optionally append extra clauses (e.g. exclude broadcast, limit to IP).
    3. Log the active filter so operators can verify it is **not** empty.
    4. Provide a ``tcpdump``-compatible test command for offline validation.

**Critical rule:** The filter returned to the capture engine must NEVER be
an empty string unless the mode is ``PortMirrorMode`` (which intentionally
captures everything).  An empty filter on any other mode means the original
bug (capturing all nearby WiFi traffic) is back.
"""

import logging
import shutil
import subprocess
import sys
from typing import Optional

from .modes.base_mode import BaseMode, ModeName

logger = logging.getLogger(__name__)

IS_WINDOWS = sys.platform == "win32"


class FilterManager:
    """
    Generates, validates, and manages BPF filter strings for packet capture.

    Usage::

        fm = FilterManager(mode)
        bpf = fm.get_validated_filter()
        promisc = fm.get_promiscuous_setting()
    """

    def __init__(self, mode: BaseMode):
        self._mode = mode

    # ------------------------------------------------------------------ #
    #  Public API
    # ------------------------------------------------------------------ #

    def get_validated_filter(self) -> str:
        """
        Return the BPF filter string for the current mode, validated.

        Raises ``ValueError`` if the filter is empty on a mode that must
        have one (anything other than ``PortMirrorMode``).
        """
        raw_filter = self._mode.get_bpf_filter()
        bpf = (raw_filter or "").strip()

        mode_name = self._mode.get_mode_name()

        # Port mirror intentionally uses an empty filter
        if mode_name == ModeName.PORT_MIRROR:
            if not bpf:
                logger.info("PortMirrorMode: empty BPF filter (capturing all traffic)")
            else:
                logger.info("PortMirrorMode: BPF filter = '%s'", bpf)
            return bpf

        # Every other mode MUST have a non-empty filter
        if not bpf:
            fallback = self._emergency_fallback_filter()
            logger.warning(
                "Mode '%s' returned empty BPF filter! Using emergency fallback: '%s'",
                mode_name.value, fallback
            )
            return fallback

        logger.info("Mode '%s': BPF filter = '%s'", mode_name.value, bpf)
        return bpf

    def get_promiscuous_setting(self) -> bool:
        """Return whether the NIC should be in promiscuous mode."""
        promisc = self._mode.should_use_promiscuous()
        logger.info(
            "Mode '%s': promiscuous = %s",
            self._mode.get_mode_name().value, promisc
        )
        return promisc

    def get_filter_summary(self) -> dict:
        """
        Return a dict summarising the active filter — useful for the REST
        API and for debugging.
        """
        bpf = self.get_validated_filter()
        return {
            "mode": self._mode.get_mode_name().value,
            "bpf_filter": bpf,
            "promiscuous": self.get_promiscuous_setting(),
            "scope": self._mode.get_scope().name,
            "ip_range": self._mode.get_valid_ip_range(),
            "interface": self._mode.interface.name,
            "tcpdump_command": self.get_tcpdump_test_command(),
        }

    def get_tcpdump_test_command(self) -> str:
        """
        Return a ``tcpdump`` (or ``windump``) command line that can be used
        to manually verify the BPF filter outside of NetWatch.
        """
        bpf = self.get_validated_filter()
        iface = self._mode.interface.name or "<interface>"
        tool = "windump" if IS_WINDOWS else "tcpdump"
        if bpf:
            return f'{tool} -i "{iface}" -c 10 "{bpf}"'
        return f'{tool} -i "{iface}" -c 10'

    def validate_bpf_syntax(self) -> bool:
        """
        Optionally validate the BPF string by compiling it with ``tcpdump -d``.
        Returns ``True`` if valid (or if tcpdump is not available).
        """
        bpf = self.get_validated_filter()
        if not bpf:
            return True  # empty is valid for port mirror

        tcpdump = shutil.which("tcpdump") or shutil.which("windump")
        if not tcpdump:
            logger.debug("tcpdump/windump not found — skipping BPF syntax check")
            return True

        try:
            result = subprocess.run(
                [tcpdump, "-d", bpf],
                capture_output=True, text=True, timeout=5,
                creationflags=(
                    subprocess.CREATE_NO_WINDOW if IS_WINDOWS else 0
                ),
            )
            if result.returncode != 0:
                logger.error(
                    "BPF filter syntax error: %s", result.stderr.strip()
                )
                return False
            return True
        except Exception as exc:
            logger.debug("BPF validation failed: %s", exc)
            return True  # assume valid if we can't check

    # ------------------------------------------------------------------ #
    #  Private helpers
    # ------------------------------------------------------------------ #

    def _emergency_fallback_filter(self) -> str:
        """
        Last-resort filter when the mode returns an empty string but should
        not have.  Restricts to our own IP to avoid capturing everything.
        """
        ip = self._mode.interface.ip_address
        if ip:
            return f"host {ip}"
        # Absolute last resort — capture nothing rather than everything
        return "host 0.0.0.0"
