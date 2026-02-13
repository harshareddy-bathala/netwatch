"""
backend - Flask Backend Package
================================

This package contains the Flask application and API routes.
"""

from backend.app import create_app
from backend.routes import register_routes

__all__ = ['create_app', 'register_routes']
