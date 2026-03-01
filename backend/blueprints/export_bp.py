"""
export_bp.py - Data Export Endpoints Blueprint
================================================
"""

import csv
import io
import json
import logging
from datetime import datetime

from flask import Blueprint, Response, jsonify, request

from config import ENABLE_DATA_EXPORT
from database.db_handler import get_traffic_summary, get_all_devices
from backend.helpers import handle_errors

logger = logging.getLogger(__name__)

export_bp = Blueprint('export', __name__)


@export_bp.route('/api/export/<fmt>')
@handle_errors
def export_data(fmt):
    """Export traffic or device data as CSV or JSON."""
    if not ENABLE_DATA_EXPORT:
        return jsonify({'error': 'Data export is disabled', 'code': 'DISABLED'}), 403

    if fmt not in ('csv', 'json'):
        return jsonify({'error': "Format must be 'csv' or 'json'", 'code': 'VALIDATION'}), 400

    export_type = request.args.get('type', 'devices')
    hours = request.args.get('hours', 24, type=int)
    hours = min(max(hours, 1), 168)
    device_ip = request.args.get('device_ip', None)

    if export_type == 'traffic':
        rows = get_traffic_summary(hours=hours, device_ip=device_ip)
        ip_tag = f'_{device_ip}' if device_ip else ''
        filename = f'netwatch_traffic{ip_tag}_{datetime.now():%Y%m%d_%H%M%S}'
    else:
        result = get_all_devices(limit=10000, offset=0)
        rows = result if isinstance(result, list) else result.get('devices', [])
        filename = f'netwatch_devices_{datetime.now():%Y%m%d_%H%M%S}'

    if fmt == 'json':
        payload = json.dumps(rows, indent=2, default=str)
        return Response(
            payload, mimetype='application/json',
            headers={'Content-Disposition': f'attachment; filename="{filename}.json"'},
        )

    # CSV
    if not rows:
        return Response(
            '', mimetype='text/csv',
            headers={'Content-Disposition': f'attachment; filename="{filename}.csv"'},
        )

    first = rows[0] if isinstance(rows[0], dict) else {}
    fieldnames = list(first.keys())

    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction='ignore')
    writer.writeheader()
    for row in rows:
        if isinstance(row, dict):
            writer.writerow(row)

    return Response(
        buf.getvalue(), mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename="{filename}.csv"'},
    )
