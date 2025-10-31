"""
Basic tests for streamripper package.
"""

import pytest
import sys
import os

# Add src to path for testing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import streamripper
from streamripper import sanitize_url_for_filename


def test_package_import():
    """Test that the package can be imported."""
    assert streamripper.__version__ == "0.1.0"
    assert streamripper.__author__ == "Paul Philippov"


def test_sanitize_url_for_filename():
    """Test URL sanitization for filenames."""
    # Test basic URL
    url = "rtsp://example.com/stream"
    result = sanitize_url_for_filename(url)
    assert result == "rtsp_example_com_stream"

    # Test URL with credentials
    url = "rtsp://user:pass@example.com/stream"
    result = sanitize_url_for_filename(url)
    assert result == "rtsp_example_com_stream"

    # Test URL with special characters and port
    url = "rtsp://example.com:554/stream?param=value&other=test"
    result = sanitize_url_for_filename(url)
    assert result == "rtsp_example_com_554_stream_param_value_other_test"

    # Test IP address with credentials
    url = "rtsp://thingino:thingino@192.168.88.33/ch0"
    result = sanitize_url_for_filename(url)
    assert result == "rtsp_192_168_88_33_ch0"


def test_module_exports():
    """Test that expected functions are exported."""
    assert hasattr(streamripper, 'analyze_rtsp_stream')
    assert hasattr(streamripper, 'generate_video_chart')
    assert hasattr(streamripper, 'sanitize_url_for_filename')


if __name__ == "__main__":
    pytest.main([__file__])
