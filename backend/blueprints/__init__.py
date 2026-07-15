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
from backend.blueprints.health import health_bp
from backend.blueprints.twin_bp import twin_bp
from backend.blueprints.forecast_bp import forecast_bp

ALL_BLUEPRINTS = [
    devices_bp,
    alerts_bp,
    bandwidth_bp,
    discovery_bp,
    interface_bp,
    system_bp,
    export_bp,
    health_bp,
    twin_bp,
    forecast_bp,
]

__all__ = [
    'ALL_BLUEPRINTS',
    'devices_bp', 'alerts_bp', 'bandwidth_bp', 'discovery_bp',
    'interface_bp', 'system_bp', 'export_bp', 'health_bp', 'twin_bp',
    'forecast_bp',
]
