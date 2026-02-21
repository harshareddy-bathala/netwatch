"""
Capture Strategy Stubs
=======================

Each strategy encapsulates mode-specific capture setup logic
(BPF filter compilation, promiscuous-mode toggling, interface
selection) so that ``CaptureEngine`` can delegate to the correct
strategy based on the active ``BaseMode``.
"""

from .ethernet_strategy import EthernetCaptureStrategy
from .mirror_strategy import MirrorCaptureStrategy

__all__ = [
    "EthernetCaptureStrategy",
    "MirrorCaptureStrategy",
]
