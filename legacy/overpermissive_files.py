#!/usr/bin/env python3
"""
Overpermissive Files Scanner - Legacy wrapper for BSOT
This script now calls the BSOT toolkit for backward compatibility.

Usage: python3 overpermissive_files.py <directory>
New usage: python3 bsot.py file permissions <directory>
"""

import sys
import subprocess

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 overpermissive_files.py <directory>")
        print("\nNote: This tool is now part of BSOT toolkit.")
        print("Use: python3 bsot.py file permissions <directory>")
        sys.exit(1)

    directory = sys.argv[1]

    # Call the BSOT toolkit
    cmd = [sys.executable, 'bsot.py', 'file', 'permissions', directory]
    subprocess.run(cmd)

if __name__ == '__main__':
    main()
