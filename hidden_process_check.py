# checks if a process running doesnt have the files on disk, indicating malware

import os
import subprocess
import hashlib
from pathlib import Path
import platform
import requests
import time
import json

# You'll need to set your VirusTotal API key
VT_API_KEY = os.getenv('VT_API_KEY')
VT_API_URL = 'https://www.virustotal.com/vtapi/v2/file/report'

def calculate_checksum(filepath):
    """Calculate SHA-256 checksum of a file"""
    try:
        # Only calculate checksum for regular files
        if not os.path.isfile(filepath):
            return None
        with open(filepath, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except (FileNotFoundError, PermissionError, IsADirectoryError):
        return None

def check_virustotal(checksum):
    """Check file hash against VirusTotal"""
    if not VT_API_KEY:
        print("Warning: VT_API_KEY not set. Skipping VirusTotal checks.")
        return None
        
    try:
        params = {'apikey': VT_API_KEY, 'resource': checksum}
        response = requests.get(VT_API_URL, params=params)
        if response.status_code == 200:
            result = response.json()
            return result
        return None
    except Exception as e:
        print(f"Error checking VirusTotal: {e}")
        return None

def get_process_path(pid):
    """Get the executable path for a process based on the OS"""
    system = platform.system()
    
    if system == 'Linux':
        try:
            return os.readlink(f'/proc/{pid}/exe')
        except (FileNotFoundError, PermissionError):
            return None
    elif system == 'Darwin':  # macOS
        try:
            # Use lsof to get the executable path
            cmd = ['lsof', '-p', str(pid), '-F', 'n']
            output = subprocess.check_output(cmd).decode('utf-8')
            for line in output.splitlines():
                if line.startswith('n'):
                    path = line[1:]  # Remove the 'n' prefix
                    # Skip special paths and directories
                    if path in ['/', '/dev/null', '/dev/zero'] or os.path.isdir(path):
                        continue
                    return path
        except (subprocess.SubprocessError, FileNotFoundError):
            return None
    return None

def is_suspicious_process(process):
    """Check if a process is suspicious based on various criteria"""
    cmd = process.get('COMMAND', '')
    pid = process.get('PID', '')
    
    # Skip kernel processes and system processes
    system_processes = [
        'kernel_task', 'launchd', 'WindowServer', 'Finder',  # macOS
        'systemd', 'init', 'kthreadd', 'ksoftirqd',  # Linux
        'ps', 'lsof'  # Our own tools
    ]
    
    if cmd.startswith('[') or any(sys_proc in cmd for sys_proc in system_processes):
        return False, None
        
    # Get the executable path
    exe_path = get_process_path(pid)
    if exe_path is None:
        # Only flag as suspicious if we can't get the path AND it's not a known system process
        return False, None
        
    # Check if executable exists and is a regular file
    if not os.path.isfile(exe_path):
        return False, None
        
    # Calculate checksum
    checksum = calculate_checksum(exe_path)
    if checksum is None:
        return False, None
        
    # Check VirusTotal
    vt_result = check_virustotal(checksum)
    if vt_result and vt_result.get('positives', 0) > 0:
        return True, {
            'type': 'virustotal',
            'details': f"Detected by {vt_result['positives']} antivirus engines",
            'path': exe_path,
            'checksum': checksum
        }
        
    # Check for suspicious indicators
    suspicious_indicators = [
        # Add paths that should be suspicious
        '/tmp/', '/var/tmp/',  # Temporary directories
        '/dev/shm/',  # Linux shared memory
        '/private/var/folders/',  # macOS temp
    ]
    
    if any(indicator in exe_path for indicator in suspicious_indicators):
        return True, {
            'type': 'suspicious_location',
            'details': f"Process running from suspicious location",
            'path': exe_path,
            'checksum': checksum
        }
        
    return False, None

def get_processes():
    """Get process list based on the OS"""
    system = platform.system()
    
    if system == 'Linux':
        cmd = ['ps', 'aux']
    elif system == 'Darwin':  # macOS
        cmd = ['ps', 'aux']
    else:
        raise SystemError("Unsupported operating system")
        
    output = subprocess.Popen(cmd, stdout=subprocess.PIPE).stdout.readlines()
    # Decode bytes to string
    output = [line.decode('utf-8') for line in output]
    headers = [h for h in ' '.join(output[0].strip().split()).split() if h]
    raw_data = map(lambda s: s.strip().split(None, len(headers) - 1), output[1:])
    return [dict(zip(headers, r)) for r in raw_data]

def main():
    print("Scanning for suspicious processes...")
    print(f"Operating System: {platform.system()}")
    suspicious_found = False
    
    for process in get_processes():
        is_suspicious, details = is_suspicious_process(process)
        if is_suspicious:
            suspicious_found = True
            print("\nSUSPICIOUS PROCESS DETECTED:")
            print(f"PID: {process.get('PID', 'N/A')}")
            print(f"User: {process.get('USER', 'N/A')}")
            print(f"Command: {process.get('COMMAND', 'N/A')}")
            print(f"CPU: {process.get('%CPU', 'N/A')}%")
            print(f"Memory: {process.get('%MEM', 'N/A')}%")
            if details:
                print(f"Reason: {details['type']}")
                print(f"Details: {details['details']}")
                print(f"Path: {details['path']}")
                print(f"SHA-256: {details['checksum']}")
            print("-" * 50)
    
    if not suspicious_found:
        print("No suspicious processes detected.")

if __name__ == '__main__':
    main()
