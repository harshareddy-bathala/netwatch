"""
blueprints - Flask Blueprint Package
======================================
"""

from backend.blueprints.devices_bp import devices_bp
from backend.blueprints.alerts_bp import alerts_bp
from backend.blueprints.bandwidth_bp import bandwidth_bp
from backend.blueprints.discovery_bp import discovery_bp
from backend.blueprints.interface_bp import interface_bp
from backend.blueprints.system_bp import system_bp
from backend.blueprints.export_bp import export_bp

ALL_BLUEPRINTS = [
    devices_bp,
    alerts_bp,
    bandwidth_bp,
    discovery_bp,
    interface_bp,
    system_bp,
    export_bp,
]

__all__ = [
    'ALL_BLUEPRINTS',
    'devices_bp', 'alerts_bp', 'bandwidth_bp', 'discovery_bp',
    'interface_bp', 'system_bp', 'export_bp',
]
