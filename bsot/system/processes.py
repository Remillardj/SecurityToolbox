"""
Process Analyzer
Monitor and analyze running processes.
"""

import os
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field


@dataclass
class ProcessInfo:
    """Information about a running process."""
    pid: int
    ppid: int = 0
    name: str = ""
    exe: str = ""
    cmdline: str = ""
    username: str = ""
    status: str = ""
    
    # Resource usage
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    memory_rss: int = 0  # Resident memory in bytes
    
    # Network
    connections: List[Dict[str, Any]] = field(default_factory=list)
    
    # Flags
    is_suspicious: bool = False
    suspicious_reasons: List[str] = field(default_factory=list)
    
    # File hash
    file_hash: str = ""
    
    def to_dict(self) -> dict:
        return {
            'pid': self.pid,
            'ppid': self.ppid,
            'name': self.name,
            'exe': self.exe,
            'cmdline': self.cmdline,
            'username': self.username,
            'status': self.status,
            'cpu_percent': self.cpu_percent,
            'memory_percent': self.memory_percent,
            'memory_mb': round(self.memory_rss / 1024 / 1024, 2),
            'connections': len(self.connections),
            'is_suspicious': self.is_suspicious,
            'suspicious_reasons': self.suspicious_reasons,
        }


class ProcessAnalyzer:
    """
    Analyze running processes for suspicious activity.
    """
    
    # Suspicious process names (exact match only)
    SUSPICIOUS_NAMES_EXACT = {
        'nc', 'ncat', 'netcat',  # Reverse shells
        'socat',
        'meterpreter',
        'mimikatz',
        'psexec',
        'procdump',
        'lazagne',
        'chisel',
        'plink',
        'ngrok',
        'frp', 'frpc', 'frps',
    }
    
    # Suspicious patterns that can appear anywhere in name
    SUSPICIOUS_NAME_PATTERNS = [
        'meterpreter',
        'mimikatz',
        'cobaltstrike',
        'beacon',
    ]
    
    # Known safe processes that match suspicious patterns (allowlist)
    SAFE_PROCESSES = {
        'findmybeaconingd',  # Apple Find My service (matches "beacon")
    }
    
    # Known safe staging paths (macOS updates)
    SAFE_DELETED_PATHS = [
        '/private/var/db/com.apple.xpc.roleaccountd.staging/',
    ]
    
    # Suspicious paths
    SUSPICIOUS_PATHS = [
        '/tmp/',
        '/dev/shm/',
        '/var/tmp/',
        'Temp\\',
        'AppData\\Local\\Temp\\',
    ]
    
    def __init__(self):
        try:
            import psutil
            self.psutil = psutil
        except ImportError:
            self.psutil = None
    
    def list_processes(self, suspicious_only: bool = False) -> List[ProcessInfo]:
        """
        List all running processes.
        
        Args:
            suspicious_only: Only return suspicious processes
            
        Returns:
            List of ProcessInfo
        """
        if not self.psutil:
            return []
        
        processes = []
        
        for proc in self.psutil.process_iter(['pid', 'ppid', 'name', 'exe', 'cmdline', 
                                               'username', 'status', 'cpu_percent', 
                                               'memory_percent', 'memory_info']):
            try:
                info = proc.info
                
                process = ProcessInfo(
                    pid=info['pid'],
                    ppid=info.get('ppid', 0),
                    name=info.get('name', ''),
                    exe=info.get('exe', '') or '',
                    cmdline=' '.join(info.get('cmdline', []) or []),
                    username=info.get('username', ''),
                    status=info.get('status', ''),
                    cpu_percent=info.get('cpu_percent', 0) or 0,
                    memory_percent=info.get('memory_percent', 0) or 0,
                )
                
                if info.get('memory_info'):
                    process.memory_rss = info['memory_info'].rss
                
                # Check for suspicious indicators
                self._check_suspicious(process)
                
                if suspicious_only and not process.is_suspicious:
                    continue
                
                processes.append(process)
                
            except (self.psutil.NoSuchProcess, self.psutil.AccessDenied, 
                    self.psutil.ZombieProcess):
                continue
        
        return processes
    
    def get_process(self, pid: int) -> Optional[ProcessInfo]:
        """Get detailed info about a specific process."""
        if not self.psutil:
            return None
        
        try:
            proc = self.psutil.Process(pid)
            
            process = ProcessInfo(
                pid=pid,
                ppid=proc.ppid(),
                name=proc.name(),
                exe=proc.exe() or '',
                cmdline=' '.join(proc.cmdline() or []),
                username=proc.username(),
                status=proc.status(),
                cpu_percent=proc.cpu_percent(),
                memory_percent=proc.memory_percent(),
                memory_rss=proc.memory_info().rss,
            )
            
            # Get connections
            try:
                for conn in proc.connections():
                    process.connections.append({
                        'local': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else '',
                        'remote': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else '',
                        'status': conn.status,
                    })
            except (self.psutil.AccessDenied, AttributeError):
                pass
            
            self._check_suspicious(process)
            
            return process
            
        except (self.psutil.NoSuchProcess, self.psutil.AccessDenied):
            return None
    
    def _check_suspicious(self, process: ProcessInfo):
        """Check process for suspicious indicators."""
        name_lower = process.name.lower()
        exe_lower = process.exe.lower()
        cmdline_lower = process.cmdline.lower()
        
        # Skip known safe processes
        if name_lower in self.SAFE_PROCESSES:
            return
        
        # Check suspicious names (exact match)
        if name_lower in self.SUSPICIOUS_NAMES_EXACT:
            process.is_suspicious = True
            process.suspicious_reasons.append(f"Suspicious process name: {name_lower}")
        
        # Check suspicious patterns (substring match for known malware names)
        for pattern in self.SUSPICIOUS_NAME_PATTERNS:
            if pattern in name_lower:
                process.is_suspicious = True
                process.suspicious_reasons.append(f"Suspicious process pattern: {pattern}")
        
        # Check suspicious paths
        for sus_path in self.SUSPICIOUS_PATHS:
            if sus_path.lower() in exe_lower:
                process.is_suspicious = True
                process.suspicious_reasons.append(f"Running from suspicious path: {sus_path}")
        
        # Check for deleted binary (but allow known safe staging paths)
        if process.exe and not os.path.exists(process.exe):
            is_safe_staging = any(safe_path in process.exe for safe_path in self.SAFE_DELETED_PATHS)
            if not is_safe_staging:
                process.is_suspicious = True
                process.suspicious_reasons.append("Binary has been deleted")
        
        # Check for hidden process (starts with .)
        if process.name.startswith('.'):
            process.is_suspicious = True
            process.suspicious_reasons.append("Hidden process name")
        
        # Check for script execution (exact match on interpreter name)
        script_interpreters = {'python', 'python3', 'perl', 'bash', 'sh', 'zsh', 'ruby', 'php', 'node'}
        if name_lower in script_interpreters and 'http' in cmdline_lower:
            process.is_suspicious = True
            process.suspicious_reasons.append("Script interpreter making HTTP connections")
    
    def get_network_connections(self) -> List[Dict[str, Any]]:
        """Get all network connections with process info."""
        if not self.psutil:
            return []
        
        connections = []
        
        try:
            conn_list = self.psutil.net_connections()
        except self.psutil.AccessDenied:
            # On macOS, this requires root. Re-raise for CLI to handle.
            raise
        except Exception:
            return []
        
        for conn in conn_list:
            try:
                proc_info = {}
                if conn.pid:
                    try:
                        proc = self.psutil.Process(conn.pid)
                        proc_info = {
                            'pid': conn.pid,
                            'name': proc.name(),
                            'username': proc.username(),
                        }
                    except (self.psutil.NoSuchProcess, self.psutil.AccessDenied):
                        proc_info = {'pid': conn.pid}
                
                connections.append({
                    'local': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else '',
                    'remote': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else '',
                    'status': conn.status,
                    'process': proc_info,
                })
            except Exception:
                continue
        
        return connections

