"""
app.py - Flask Application Factory
====================================

Production-ready Flask application with CORS, error handling, and static file serving.
"""

import os
import sys
import logging
from datetime import datetime

from flask import Flask, jsonify, send_from_directory, request
from flask_cors import CORS

# Add project root to path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from config import (
    FLASK_HOST, FLASK_PORT, FLASK_DEBUG,
    CORS_ORIGINS, CORS_ALLOW_CREDENTIALS,
    APP_NAME, APP_VERSION, APP_ENV
)
from backend.routes import register_routes
from backend.middleware import register_middleware

# Setup logging
logger = logging.getLogger(__name__)

# Track application start time
APP_START_TIME = datetime.now()


def create_app(config_override: dict = None) -> Flask:
    """
    Create and configure the Flask application.
    
    Args:
        config_override: Optional dictionary of config overrides
        
    Returns:
        Configured Flask application instance
    """
    # Create Flask app with static folder pointing to frontend
    app = Flask(
        __name__,
        static_folder=os.path.join(PROJECT_ROOT, 'frontend'),
        static_url_path=''
    )
    
    # Configure app
    app.config['JSON_SORT_KEYS'] = False
    app.config['JSONIFY_PRETTYPRINT_REGULAR'] = APP_ENV == 'development'
    
    if config_override:
        app.config.update(config_override)
    
    # Enable CORS — restrict origins in production
    CORS(
        app,
        origins=CORS_ORIGINS if APP_ENV == 'production' else ['http://localhost:5000', 'http://127.0.0.1:5000'],
        supports_credentials=CORS_ALLOW_CREDENTIALS
    )
    
    # Reduce werkzeug logging verbosity to WARNING level
    werkzeug_logger = logging.getLogger('werkzeug')
    werkzeug_logger.setLevel(logging.WARNING)
    
    # Set Flask app logger to WARNING
    app.logger.setLevel(logging.WARNING)
    
    # Register security middleware (auth + rate limiting)
    register_middleware(app)
    
    # Register API routes
    register_routes(app)
    
    # =========================================================================
    # STATIC FILE SERVING (Frontend)
    # =========================================================================
    
    @app.route('/')
    def serve_index():
        """Serve the SPA entry point."""
        return send_from_directory(app.static_folder, 'index.html')
    
    @app.route('/devices')
    @app.route('/alerts')
    def serve_spa_routes():
        """SPA client-side routes — always return index.html."""
        return send_from_directory(app.static_folder, 'index.html')
    
    @app.route('/<path:filename>')
    def serve_static(filename):
        """Serve static files (CSS, JS, images)."""
        return send_from_directory(app.static_folder, filename)
    
    # =========================================================================
    # ERROR HANDLERS
    # =========================================================================
    
    @app.errorhandler(400)
    def handle_bad_request(error):
        """Handle bad request errors."""
        return jsonify({
            'error': 'Bad Request',
            'message': str(error.description) if hasattr(error, 'description') else 'Invalid request'
        }), 400
    
    @app.errorhandler(404)
    def handle_not_found(error):
        """Handle 404 errors."""
        if request.path.startswith('/api/'):
            return jsonify({
                'error': 'Not Found',
                'message': f'Endpoint {request.path} not found'
            }), 404
        try:
            return send_from_directory(app.static_folder, 'index.html')
        except Exception:
            return jsonify({'error': 'Not Found'}), 404
    
    @app.errorhandler(405)
    def handle_method_not_allowed(error):
        """Handle method not allowed errors."""
        return jsonify({
            'error': 'Method Not Allowed',
            'message': f'Method {request.method} not allowed for {request.path}'
        }), 405
    
    @app.errorhandler(500)
    def handle_internal_error(error):
        """Handle internal server errors — never leak details."""
        logger.error("Internal error: %s", error)
        return jsonify({
            'error': 'Internal Server Error',
            'message': 'An unexpected error occurred'
        }), 500
    
    # =========================================================================
    # HEALTH CHECK
    # =========================================================================
    
    @app.route('/health')
    def health_check():
        """Basic health check endpoint (lightweight, for load balancers)."""
        return jsonify({
            'status': 'healthy',
            'version': APP_VERSION,
            'timestamp': datetime.now().isoformat()
        })
    
    @app.route('/api/info')
    def app_info():
        """Return application information."""
        uptime = (datetime.now() - APP_START_TIME).total_seconds()
        return jsonify({
            'name': APP_NAME,
            'version': APP_VERSION,
            'environment': APP_ENV,
            'uptime_seconds': round(uptime, 2),
            'uptime_formatted': format_uptime(uptime)
        })
    
    logger.info(f"{APP_NAME} v{APP_VERSION} initialized ({APP_ENV} mode)")
    
    return app


def format_uptime(seconds: float) -> str:
    """Format uptime in human-readable format."""
    days = int(seconds // 86400)
    hours = int((seconds % 86400) // 3600)
    minutes = int((seconds % 3600) // 60)
    secs = int(seconds % 60)
    
    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0:
        parts.append(f"{minutes}m")
    parts.append(f"{secs}s")
    
    return ' '.join(parts)


# For running directly
if __name__ == '__main__':
    app = create_app()
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=FLASK_DEBUG)
