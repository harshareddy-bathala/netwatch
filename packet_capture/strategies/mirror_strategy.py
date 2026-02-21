"""
mirror_strategy.py - Capture Strategy for SPAN / Port Mirror
==============================================================

Manages promiscuous-mode setup for full mirror capture.
"""

import logging
import sys
from typing import Optional

logger = logging.getLogger(__name__)


class MirrorCaptureStrategy:
    """Capture strategy for :class:`PortMirrorMode`."""

    def __init__(self, mode):
        self._mode = mode
        self._promisc_was_enabled = False

    # ------------------------------------------------------------------ #
    #  Lifecycle
    # ------------------------------------------------------------------ #

    def setup(self) -> None:
        """Enable promiscuous mode on the NIC for full mirror capture."""
        iface = self._mode.interface.name
        logger.info(
            "MirrorCaptureStrategy.setup() — iface=%s (no BPF filter, promiscuous ON)",
            iface,
        )
        try:
            if sys.platform != 'win32':
                import subprocess
                subprocess.run(
                    ['ip', 'link', 'set', iface, 'promisc', 'on'],
                    check=True, capture_output=True, timeout=5,
                )
                self._promisc_was_enabled = True
                logger.info("Promiscuous mode enabled on %s", iface)
            else:
                # Windows: Npcap/WinPcap handles promisc via sniff(promisc=True)
                self._promisc_was_enabled = True
        except Exception as exc:
            logger.warning("Could not enable promiscuous mode on %s: %s", iface, exc)

    def teardown(self) -> None:
        """Disable promiscuous mode if we enabled it."""
        iface = self._mode.interface.name
        logger.info("MirrorCaptureStrategy.teardown() — iface=%s", iface)
        if self._promisc_was_enabled and sys.platform != 'win32':
            try:
                import subprocess
                subprocess.run(
                    ['ip', 'link', 'set', iface, 'promisc', 'off'],
                    check=True, capture_output=True, timeout=5,
                )
                logger.info("Promiscuous mode disabled on %s", iface)
            except Exception as exc:
                logger.warning("Could not disable promiscuous mode on %s: %s", iface, exc)
        self._promisc_was_enabled = False

    # ------------------------------------------------------------------ #
    #  Query helpers (used by CaptureEngine)
    # ------------------------------------------------------------------ #

    @property
    def bpf_filter(self) -> str:
        """Mirror mode uses no filter — capture everything."""
        return ""

    @property
    def use_promiscuous(self) -> bool:
        return True

    @property
    def interface_name(self) -> str:
        return self._mode.interface.name

    @property
    def subnet_cidr(self) -> Optional[str]:
        return self._mode.get_valid_ip_range()
