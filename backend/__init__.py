"""
backend - Flask Backend Package
================================

This package contains the Flask application and API routes (Blueprints).
"""

from backend.app import create_app
from backend.blueprints import ALL_BLUEPRINTS

__all__ = ['create_app', 'ALL_BLUEPRINTS']
