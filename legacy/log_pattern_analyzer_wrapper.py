#!/usr/bin/env python3
"""
Log Pattern Analyzer - Legacy wrapper for BSOT
This script now calls the BSOT toolkit for backward compatibility.

Usage: python3 log_pattern_analyzer_wrapper.py <log_file> [options]
New usage: python3 bsot.py logs analyze <log_file> [options]
"""

import sys
import subprocess
import argparse

def main():
    # Parse arguments to convert to BSOT format
    parser = argparse.ArgumentParser(description='Analyze log files (legacy wrapper)')
    parser.add_argument('log_file', help='Path to the log file to analyze')
    parser.add_argument('-o', '--output', choices=['text', 'json'], default='text',
                       help='Output format (default: text)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('-p', '--patterns', type=str,
                       help='JSON file containing custom patterns to search for')
    parser.add_argument('-f', '--focus', type=str,
                       help='Focus on specific information: ip, brute_force, username, compromised, email, url')
    parser.add_argument('-q', '--query', type=str,
                       help='Ask a specific question')

    args = parser.parse_args()

    # Build BSOT command
    cmd = [sys.executable, 'bsot.py', 'logs', 'analyze', args.log_file]

    if args.output:
        cmd.extend(['--output', args.output])
    if args.verbose:
        cmd.append('--verbose')
    if args.patterns:
        cmd.extend(['--patterns', args.patterns])
    if args.focus:
        cmd.extend(['--focus', args.focus])
    if args.query:
        cmd.extend(['--query', args.query])

    print("Note: This tool is now part of BSOT toolkit.")
    print(f"Running: bsot logs analyze {args.log_file}\n")

    # Call the BSOT toolkit
    subprocess.run(cmd)

if __name__ == '__main__':
    main()
