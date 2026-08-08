"""Pytest setup for the bridge package when tests run from the repository root."""

from pathlib import Path
import sys


BRIDGE_ROOT = Path(__file__).resolve().parents[1]
if str(BRIDGE_ROOT) not in sys.path:
    sys.path.insert(0, str(BRIDGE_ROOT))
