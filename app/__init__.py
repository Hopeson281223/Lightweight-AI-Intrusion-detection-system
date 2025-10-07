# app/__init__.py
"""
LAI-IDS (Lightweight AI-Powered Intrusion Detection System)
A real-time network intrusion detection system using machine learning.
"""

__version__ = "0.1.0"
__author__ = "Hopeson Benderi"
__description__ = "Lightweight AI-Powered Intrusion Detection System"

# Import key components to make them easily accessible
from .main import app

__all__ = ["app"]