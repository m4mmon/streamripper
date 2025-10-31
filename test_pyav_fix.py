#!/usr/bin/env python3
"""
Test script to verify PyAV fixes work correctly.
"""

import sys
import os

# Add the src directory to the path for testing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def test_imports():
    """Test that we can import the modules without errors."""
    try:
        import av
        print(f"✓ PyAV imported successfully (version: {av.__version__})")
        
        # Test that we can access av.open
        print(f"✓ av.open available: {hasattr(av, 'open')}")
        
        # Test exception handling
        try:
            # This should fail but we want to see what exception type we get
            container = av.open("nonexistent://fake.url", timeout=1)
        except Exception as e:
            print(f"✓ Exception type for invalid URL: {type(e).__name__}")
            print(f"  Exception module: {type(e).__module__}")
        
        return True
    except ImportError as e:
        print(f"✗ Failed to import PyAV: {e}")
        return False

def test_cli_import():
    """Test that we can import the CLI module."""
    try:
        from streamripper.cli import create_parser
        parser = create_parser()
        
        # Test parsing with save-stream
        args = parser.parse_args(["rtsp://test.com/stream", "--save-stream"])
        print(f"✓ CLI parsing works: save_stream = {args.save_stream}")
        return True
    except Exception as e:
        print(f"✗ Failed to import CLI: {e}")
        return False

if __name__ == "__main__":
    print("Testing PyAV fixes...")
    print("-" * 40)
    
    success = True
    success &= test_imports()
    success &= test_cli_import()
    
    print("-" * 40)
    if success:
        print("✓ All tests passed!")
    else:
        print("✗ Some tests failed!")
    
    sys.exit(0 if success else 1)
