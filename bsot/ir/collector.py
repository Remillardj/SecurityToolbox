"""
Artifact Collector
Collect forensic artifacts from systems.
"""

import os
import platform
import socket
import json
import hashlib
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field


@dataclass
class CollectionManifest:
    """Collection manifest."""
    hostname: str = ""
    collection_time: str = ""
    collected_by: str = ""
    platform: str = ""
    profile: str = ""
    
    artifacts: List[Dict[str, Any]] = field(default_factory=list)
    
    # Summary
    total_files: int = 0
    total_bytes: int = 0
    
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            'metadata': {
                'hostname': self.hostname,
                'collection_time': self.collection_time,
                'collected_by': self.collected_by,
                'platform': self.platform,
                'profile': self.profile,
            },
            'artifacts': self.artifacts,
            'summary': {
                'total_files': self.total_files,
                'total_bytes': self.total_bytes,
            },
            'errors': self.errors,
        }


class ArtifactCollector:
    """
    Collect forensic artifacts from systems.
    
    Profiles:
    - quick: Running processes, network connections, logged-in users
    - standard: + browser history, recent files, scheduled tasks
    - full: + full file listings, installed software, user accounts
    """
    
    def __init__(self, output_dir: str = None):
        """
        Initialize collector.
        
        Args:
            output_dir: Output directory (default: ./bsot-collection-{timestamp})
        """
        if output_dir:
            self.output_dir = Path(output_dir)
        else:
            timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
            self.output_dir = Path(f'./bsot-collection-{timestamp}')
        
        self.manifest = CollectionManifest()
        self.manifest.hostname = socket.gethostname()
        self.manifest.collection_time = datetime.now().isoformat()
        self.manifest.collected_by = os.getenv('USER', os.getenv('USERNAME', 'unknown'))
        self.manifest.platform = platform.system()
    
    def collect(self, profile: str = 'standard') -> CollectionManifest:
        """
        Collect artifacts based on profile.
        
        Args:
            profile: Collection profile (quick, standard, full)
            
        Returns:
            CollectionManifest
        """
        self.manifest.profile = profile
        
        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Quick profile
        self._collect_system_info()
        self._collect_processes()
        self._collect_network()
        self._collect_users()
        
        if profile in ('standard', 'full'):
            self._collect_scheduled_tasks()
            self._collect_startup_items()
            self._collect_recent_files()
        
        if profile == 'full':
            self._collect_installed_software()
            self._collect_user_accounts()
        
        # Write manifest
        manifest_path = self.output_dir / 'manifest.json'
        with open(manifest_path, 'w') as f:
            json.dump(self.manifest.to_dict(), f, indent=2)
        
        return self.manifest
    
    def _add_artifact(self, category: str, name: str, data: Any, save_file: bool = True):
        """Add artifact to collection."""
        artifact = {
            'category': category,
            'name': name,
            'collected_at': datetime.now().isoformat(),
        }
        
        if save_file and data:
            # Save to file
            category_dir = self.output_dir / category
            category_dir.mkdir(parents=True, exist_ok=True)
            
            file_path = category_dir / f'{name}.json'
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            
            artifact['file'] = str(file_path.relative_to(self.output_dir))
            artifact['size'] = file_path.stat().st_size
            self.manifest.total_files += 1
            self.manifest.total_bytes += artifact['size']
        
        self.manifest.artifacts.append(artifact)
    
    def _collect_system_info(self):
        """Collect basic system information."""
        import platform as plat
        
        info = {
            'hostname': socket.gethostname(),
            'platform': plat.system(),
            'platform_release': plat.release(),
            'platform_version': plat.version(),
            'architecture': plat.machine(),
            'processor': plat.processor(),
            'python_version': plat.python_version(),
            'collection_time': datetime.now().isoformat(),
        }
        
        # Network interfaces
        try:
            import psutil
            interfaces = {}
            for iface, addrs in psutil.net_if_addrs().items():
                interfaces[iface] = [{'address': a.address, 'family': str(a.family)} for a in addrs]
            info['network_interfaces'] = interfaces
        except ImportError:
            pass
        
        self._add_artifact('system', 'system_info', info)
    
    def _collect_processes(self):
        """Collect running processes."""
        processes = []
        
        try:
            import psutil
            for proc in psutil.process_iter(['pid', 'ppid', 'name', 'exe', 'cmdline', 
                                             'username', 'status', 'create_time']):
                try:
                    info = proc.info
                    processes.append({
                        'pid': info['pid'],
                        'ppid': info.get('ppid', 0),
                        'name': info.get('name', ''),
                        'exe': info.get('exe', ''),
                        'cmdline': info.get('cmdline', []),
                        'username': info.get('username', ''),
                        'status': info.get('status', ''),
                        'create_time': info.get('create_time', 0),
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except ImportError:
            self.manifest.errors.append("psutil not available for process collection")
        
        self._add_artifact('processes', 'running_processes', processes)
    
    def _collect_network(self):
        """Collect network connections."""
        connections = []
        
        try:
            import psutil
            for conn in psutil.net_connections():
                connections.append({
                    'local': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else '',
                    'remote': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else '',
                    'status': conn.status,
                    'pid': conn.pid,
                })
        except ImportError:
            self.manifest.errors.append("psutil not available for network collection")
        except Exception as e:
            self.manifest.errors.append(f"Network collection error: {e}")
        
        self._add_artifact('network', 'connections', connections)
    
    def _collect_users(self):
        """Collect logged-in users."""
        users = []
        
        try:
            import psutil
            for user in psutil.users():
                users.append({
                    'name': user.name,
                    'terminal': user.terminal or '',
                    'host': user.host or '',
                    'started': user.started,
                })
        except ImportError:
            pass
        
        self._add_artifact('users', 'logged_in_users', users)
    
    def _collect_scheduled_tasks(self):
        """Collect scheduled tasks."""
        tasks = []
        
        if platform.system() == 'Linux':
            # Collect crontabs
            cron_dirs = ['/etc/crontab', '/etc/cron.d']
            for cron_path in cron_dirs:
                path = Path(cron_path)
                if path.exists():
                    if path.is_file():
                        try:
                            tasks.append({
                                'source': str(path),
                                'content': path.read_text()
                            })
                        except PermissionError:
                            pass
        
        elif platform.system() == 'Darwin':
            # macOS Launch Agents/Daemons
            launch_dirs = [
                Path.home() / 'Library/LaunchAgents',
                Path('/Library/LaunchAgents'),
                Path('/Library/LaunchDaemons'),
            ]
            for launch_dir in launch_dirs:
                if launch_dir.exists():
                    for plist in launch_dir.glob('*.plist'):
                        try:
                            tasks.append({
                                'source': str(plist),
                                'content': plist.read_text()
                            })
                        except PermissionError:
                            pass
        
        self._add_artifact('persistence', 'scheduled_tasks', tasks)
    
    def _collect_startup_items(self):
        """Collect startup/persistence items."""
        items = []
        
        if platform.system() == 'Linux':
            # Systemd services
            systemd_dirs = ['/etc/systemd/system', '/lib/systemd/system']
            for systemd_dir in systemd_dirs:
                path = Path(systemd_dir)
                if path.exists():
                    for service in path.glob('*.service'):
                        try:
                            items.append({
                                'type': 'systemd',
                                'path': str(service),
                                'name': service.name,
                            })
                        except PermissionError:
                            pass
        
        self._add_artifact('persistence', 'startup_items', items)
    
    def _collect_recent_files(self):
        """Collect list of recently modified files."""
        recent = []
        
        # Find files modified in last 24 hours in common locations
        search_paths = [
            Path.home(),
            Path('/tmp') if platform.system() != 'Windows' else None,
        ]
        
        cutoff = datetime.now().timestamp() - 86400  # 24 hours ago
        
        for search_path in search_paths:
            if not search_path or not search_path.exists():
                continue
            
            try:
                for file_path in search_path.rglob('*'):
                    if file_path.is_file():
                        try:
                            stat = file_path.stat()
                            if stat.st_mtime > cutoff:
                                recent.append({
                                    'path': str(file_path),
                                    'size': stat.st_size,
                                    'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                                })
                        except (PermissionError, OSError):
                            pass
                    
                    # Limit to 1000 files
                    if len(recent) >= 1000:
                        break
            except PermissionError:
                pass
        
        self._add_artifact('filesystem', 'recent_files', recent)
    
    def _collect_installed_software(self):
        """Collect list of installed software."""
        software = []
        
        if platform.system() == 'Darwin':
            # macOS - check Applications folder
            apps_dir = Path('/Applications')
            if apps_dir.exists():
                for app in apps_dir.glob('*.app'):
                    software.append({
                        'name': app.stem,
                        'path': str(app),
                        'type': 'application',
                    })
        
        elif platform.system() == 'Linux':
            # Try dpkg
            try:
                import subprocess
                result = subprocess.run(['dpkg', '-l'], capture_output=True, text=True)
                for line in result.stdout.split('\n')[5:]:
                    parts = line.split()
                    if len(parts) >= 3:
                        software.append({
                            'name': parts[1],
                            'version': parts[2],
                            'type': 'dpkg',
                        })
            except Exception:
                pass
        
        self._add_artifact('software', 'installed_software', software)
    
    def _collect_user_accounts(self):
        """Collect user account information."""
        accounts = []
        
        if platform.system() in ('Linux', 'Darwin'):
            # Parse /etc/passwd
            passwd_path = Path('/etc/passwd')
            if passwd_path.exists():
                try:
                    for line in passwd_path.read_text().splitlines():
                        parts = line.split(':')
                        if len(parts) >= 7:
                            accounts.append({
                                'username': parts[0],
                                'uid': parts[2],
                                'gid': parts[3],
                                'home': parts[5],
                                'shell': parts[6],
                            })
                except PermissionError:
                    pass
        
        self._add_artifact('users', 'user_accounts', accounts)


def hash_directory(path: str, algorithm: str = 'sha256') -> Dict[str, Any]:
    """
    Hash all files in a directory for evidence integrity.
    
    Args:
        path: Directory to hash
        algorithm: Hash algorithm
        
    Returns:
        Manifest with file hashes
    """
    manifest = {
        'metadata': {
            'hostname': socket.gethostname(),
            'collection_time': datetime.now().isoformat(),
            'root_path': str(path),
            'algorithm': algorithm,
        },
        'files': [],
    }
    
    all_hashes = []
    dir_path = Path(path)
    
    for file_path in dir_path.rglob('*'):
        if file_path.is_file():
            try:
                hasher = hashlib.new(algorithm)
                with open(file_path, 'rb') as f:
                    while chunk := f.read(8192):
                        hasher.update(chunk)
                
                file_hash = hasher.hexdigest()
                all_hashes.append(file_hash)
                
                manifest['files'].append({
                    'path': str(file_path.relative_to(dir_path)),
                    'hash': file_hash,
                    'size': file_path.stat().st_size,
                    'modified': datetime.fromtimestamp(file_path.stat().st_mtime).isoformat(),
                })
            except (PermissionError, OSError):
                continue
    
    # Calculate root hash
    combined = ''.join(sorted(all_hashes))
    manifest['summary'] = {
        'total_files': len(manifest['files']),
        'total_bytes': sum(f['size'] for f in manifest['files']),
        'root_hash': hashlib.new(algorithm, combined.encode()).hexdigest(),
    }
    
    return manifest

