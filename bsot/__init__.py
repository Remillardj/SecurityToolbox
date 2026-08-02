"""
BSOT - Blue Security Ops Toolkit

A comprehensive security toolkit for blue team operations.
"""

from importlib.metadata import PackageNotFoundError, version

try:
    # pyproject.toml is the single source of truth; reading it back from the
    # installed metadata keeps the two from drifting.
    __version__ = version("bsot")
except PackageNotFoundError:  # source tree with no install
    __version__ = "0.0.0+unknown"

__author__ = "Jaryd Remillard"
