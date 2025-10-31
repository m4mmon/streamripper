"""
Streamripper - RTSP stream analyzer and video quality assessment tool.

This package provides tools for analyzing RTSP video streams, generating
quality reports, and creating visual charts of stream characteristics.
"""

__version__ = "0.1.0"
__author__ = "Paul Philippov"
__email__ = "paul@themactep.com"
__license__ = "GPL-3.0"

from .rtsp_analyzer import analyze_rtsp_stream, sanitize_url_for_filename
from .chart_generator import generate_video_chart, generate_combined_chart, generate_comprehensive_chart

__all__ = [
    "analyze_rtsp_stream",
    "sanitize_url_for_filename",
    "generate_video_chart",
    "generate_combined_chart",
    "generate_comprehensive_chart",
]
