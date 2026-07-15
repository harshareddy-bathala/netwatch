"""
forecast_bp.py - Forecasting Endpoints (Phase 2, AI-first)
===========================================================

* ``GET /api/forecast/bandwidth?horizon=30`` — total-Mbps forecast with
  confidence band and optional saturation ETA
* ``GET /api/forecast/devices?horizon=6``   — active-device-count trend

Both compute on demand from the telemetry tables (TTL-cached) and return
``available: false`` with a reason instead of failing when there is not
enough history yet.
"""

import logging

from flask import Blueprint, request

from backend.helpers import handle_errors, success_detail
from intelligence.forecast import forecast_service

logger = logging.getLogger(__name__)

forecast_bp = Blueprint('forecast', __name__)


@forecast_bp.route('/api/forecast/bandwidth', methods=['GET'])
@handle_errors
def get_bandwidth_forecast():
    """Bandwidth forecast for the dashboard chart overlay."""
    horizon = request.args.get('horizon', default=None, type=int)
    kwargs = {} if horizon is None else {"horizon_minutes": horizon}
    return success_detail(forecast_service.forecast_bandwidth(**kwargs))


@forecast_bp.route('/api/forecast/devices', methods=['GET'])
@handle_errors
def get_device_forecast():
    """Active-device-count trend forecast."""
    horizon = request.args.get('horizon', default=None, type=int)
    kwargs = {} if horizon is None else {"horizon_hours": horizon}
    return success_detail(forecast_service.forecast_devices(**kwargs))
