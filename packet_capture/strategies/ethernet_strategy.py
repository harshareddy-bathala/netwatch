"""
ethernet_strategy.py - Capture Strategy for Ethernet / Wired LAN
==================================================================

Manages promiscuous-mode setup and BPF filter compilation for Ethernet capture.
"""

import logging
import sys
from typing import Optional

logger = logging.getLogger(__name__)


class EthernetCaptureStrategy:
    """Capture strategy for :class:`EthernetMode`."""

    def __init__(self, mode):
        self._mode = mode
        self._promisc_was_enabled = False
        self._compiled_filter: Optional[str] = None

    # ------------------------------------------------------------------ #
    #  Lifecycle
    # ------------------------------------------------------------------ #

    def setup(self) -> None:
        """Enable promiscuous mode and compile the BPF filter."""
        iface = self._mode.interface.name
        bpf = self._mode.get_bpf_filter()
        self._compiled_filter = bpf

        logger.info(
            "EthernetCaptureStrategy.setup() — iface=%s, filter='%s'",
            iface, bpf,
        )

        if self._mode.should_use_promiscuous():
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
                    self._promisc_was_enabled = True
            except Exception as exc:
                logger.warning("Could not enable promiscuous mode on %s: %s", iface, exc)

        # Validate BPF filter by attempting a compile via tcpdump (Linux/macOS)
        if bpf and sys.platform != 'win32':
            try:
                import subprocess
                result = subprocess.run(
                    ['tcpdump', '-d', '-i', iface, bpf],
                    capture_output=True, text=True, timeout=5,
                )
                if result.returncode != 0:
                    logger.warning("BPF filter validation failed: %s", result.stderr.strip())
                else:
                    logger.debug("BPF filter compiled successfully")
            except FileNotFoundError:
                logger.debug("tcpdump not found — skipping BPF validation")
            except Exception as exc:
                logger.debug("BPF validation error: %s", exc)

    def teardown(self) -> None:
        """Disable promiscuous mode if we enabled it."""
        iface = self._mode.interface.name
        logger.info("EthernetCaptureStrategy.teardown() — iface=%s", iface)
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
        self._compiled_filter = None

    # ------------------------------------------------------------------ #
    #  Query helpers (used by CaptureEngine)
    # ------------------------------------------------------------------ #

    @property
    def bpf_filter(self) -> str:
        return self._compiled_filter or self._mode.get_bpf_filter()

    @property
    def use_promiscuous(self) -> bool:
        return self._mode.should_use_promiscuous()

    @property
    def interface_name(self) -> str:
        return self._mode.interface.name

    @property
    def subnet_cidr(self) -> Optional[str]:
        return self._mode.get_valid_ip_range()
