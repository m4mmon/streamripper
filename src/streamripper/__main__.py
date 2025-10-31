#!/usr/bin/env python3
"""
Main entry point for running streamripper as a module.

This allows the package to be executed with:
    python -m streamripper
"""

import sys
from .cli import main

if __name__ == "__main__":
    sys.exit(main())
