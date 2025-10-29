#!/usr/bin/env python3
"""
Hidden Process Check - Legacy wrapper for BSOT
This script now calls the BSOT toolkit for backward compatibility.

Usage: python3 hidden_process_check.py
New usage: python3 bsot.py system process-check
"""

import sys
import subprocess
import os

def main():
    # Build command
    cmd = [sys.executable, 'bsot.py', 'system', 'process-check']

    # Pass through VT_API_KEY if set
    vt_key = os.getenv('VT_API_KEY')
    if vt_key:
        cmd.extend(['--vt-api-key', vt_key])

    # Add verbose flag if requested
    if '--verbose' in sys.argv or '-v' in sys.argv:
        cmd.append('--verbose')

    print("Note: This tool is now part of BSOT toolkit.")
    print("Running: bsot system process-check\n")

    # Call the BSOT toolkit
    subprocess.run(cmd)

if __name__ == '__main__':
    main()
