"""
Case Manager
Handles case CRUD operations, artifact storage, and active case tracking.
"""

import json
import uuid
import hashlib
import shutil
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field, asdict


@dataclass
class Case:
    """Represents an investigation case."""
    id: str
    name: str
    type: str  # phishing, malware, intrusion, insider, apt
    created_at: str
    updated_at: str
    status: str  # active, closed, archived
    analyst: str
    description: str
    tags: List[str]
    severity: str  # low, medium, high, critical
    path: Path = field(default=None, repr=False)
    
    # Counts (computed)
    artifacts_count: int = 0
    iocs_count: int = 0
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            'id': self.id,
            'name': self.name,
            'type': self.type,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'status': self.status,
            'analyst': self.analyst,
            'description': self.description,
            'tags': self.tags,
            'severity': self.severity,
            'artifacts_count': self.artifacts_count,
            'iocs_count': self.iocs_count,
        }
    
    @classmethod
    def from_dict(cls, data: dict, path: Path = None) -> 'Case':
        """Create Case from dictionary."""
        return cls(
            id=data.get('id', ''),
            name=data.get('name', ''),
            type=data.get('type', 'general'),
            created_at=data.get('created_at', ''),
            updated_at=data.get('updated_at', ''),
            status=data.get('status', 'active'),
            analyst=data.get('analyst', ''),
            description=data.get('description', ''),
            tags=data.get('tags', []),
            severity=data.get('severity', 'medium'),
            path=path,
            artifacts_count=data.get('artifacts_count', 0),
            iocs_count=data.get('iocs_count', 0),
        )
    
    def save(self):
        """Save case metadata to case.json."""
        if self.path:
            self.updated_at = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
            case_file = self.path / 'case.json'
            case_file.write_text(json.dumps(self.to_dict(), indent=2))
    
    def update_counts(self):
        """Update artifact and IOC counts."""
        if not self.path:
            return
        
        # Count artifacts
        artifacts_dir = self.path / 'artifacts'
        if artifacts_dir.exists():
            self.artifacts_count = sum(1 for f in artifacts_dir.rglob('*') if f.is_file())
        
        # Count IOCs
        iocs_file = self.path / 'iocs.json'
        if iocs_file.exists():
            try:
                iocs = json.loads(iocs_file.read_text())
                self.iocs_count = len(iocs) if isinstance(iocs, list) else 0
            except Exception:
                self.iocs_count = 0


class CaseManager:
    """
    Manages investigation cases.
    """
    
    CASE_SUBDIRS = [
        'artifacts/emails',
        'artifacts/files',
        'artifacts/screenshots',
        'artifacts/logs',
        'outputs/phishing',
        'outputs/malware',
        'outputs/intel',
        'outputs/network',
        'outputs/file',
        'outputs/logs',
        'reports',
    ]
    
    def __init__(self, cases_dir: Path = None):
        """
        Initialize case manager.
        
        Args:
            cases_dir: Directory to store cases (default: ~/.bsot/cases)
        """
        if cases_dir is None:
            cases_dir = Path.home() / '.bsot' / 'cases'
        self.cases_dir = Path(cases_dir)
        self.cases_dir.mkdir(parents=True, exist_ok=True)
        
        self.active_case_file = Path.home() / '.bsot' / 'active_case'
    
    def create(
        self,
        name: str,
        case_type: str = 'general',
        description: str = '',
        analyst: str = '',
        tags: List[str] = None,
        severity: str = 'medium'
    ) -> Case:
        """
        Create a new case.
        
        Args:
            name: Case name
            case_type: Type of investigation
            description: Case description
            analyst: Analyst name
            tags: List of tags
            severity: Case severity
            
        Returns:
            Created Case object
        """
        # Sanitize name for directory
        safe_name = self._sanitize_name(name)
        case_path = self.cases_dir / safe_name
        
        if case_path.exists():
            raise ValueError(f"Case already exists: {safe_name}")
        
        # Create directory structure
        case_path.mkdir(parents=True)
        for subdir in self.CASE_SUBDIRS:
            (case_path / subdir).mkdir(parents=True, exist_ok=True)
        
        # Create case object
        now = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        case = Case(
            id=str(uuid.uuid4()),
            name=safe_name,
            type=case_type,
            created_at=now,
            updated_at=now,
            status='active',
            analyst=analyst,
            description=description,
            tags=tags or [],
            severity=severity,
            path=case_path,
        )
        
        # Save case.json
        case.save()
        
        # Create empty files
        (case_path / 'iocs.json').write_text('[]')
        (case_path / 'timeline.json').write_text('[]')
        (case_path / 'notes.md').write_text('# Investigation Notes\n\n')
        
        # Set as active
        self.set_active(case)
        
        return case
    
    def get(self, name: str) -> Optional[Case]:
        """
        Get a case by name.
        
        Args:
            name: Case name
            
        Returns:
            Case object or None
        """
        safe_name = self._sanitize_name(name)
        case_path = self.cases_dir / safe_name
        
        if not case_path.exists():
            return None
        
        case_file = case_path / 'case.json'
        if not case_file.exists():
            return None
        
        try:
            data = json.loads(case_file.read_text())
            case = Case.from_dict(data, case_path)
            case.update_counts()
            return case
        except Exception:
            return None
    
    def list_cases(
        self,
        status: str = None,
        recent: int = None
    ) -> List[Case]:
        """
        List all cases.
        
        Args:
            status: Filter by status
            recent: Limit to N most recent
            
        Returns:
            List of Case objects
        """
        cases = []
        
        for case_dir in self.cases_dir.iterdir():
            if case_dir.is_dir():
                case = self.get(case_dir.name)
                if case:
                    if status and case.status != status:
                        continue
                    cases.append(case)
        
        # Sort by created_at descending
        cases.sort(key=lambda c: c.created_at, reverse=True)
        
        if recent:
            cases = cases[:recent]
        
        return cases
    
    def set_active(self, case: Case):
        """Set a case as the active case."""
        self.active_case_file.parent.mkdir(parents=True, exist_ok=True)
        self.active_case_file.write_text(case.name)
    
    def get_active(self) -> Optional[Case]:
        """Get the currently active case."""
        if not self.active_case_file.exists():
            return None
        
        name = self.active_case_file.read_text().strip()
        if not name:
            return None
        
        return self.get(name)
    
    def clear_active(self):
        """Clear the active case."""
        if self.active_case_file.exists():
            self.active_case_file.unlink()
    
    def close(self, case: Case):
        """Close a case."""
        case.status = 'closed'
        case.save()
        
        # Clear active if this was the active case
        active = self.get_active()
        if active and active.name == case.name:
            self.clear_active()
    
    def delete(self, name: str):
        """Delete a case (use with caution)."""
        safe_name = self._sanitize_name(name)
        case_path = self.cases_dir / safe_name
        
        if case_path.exists():
            shutil.rmtree(case_path)
        
        # Clear active if this was the active case
        active = self.get_active()
        if active and active.name == safe_name:
            self.clear_active()
    
    def add_artifact(
        self,
        case: Case,
        file_path: Path,
        artifact_type: str = None
    ) -> Dict[str, Any]:
        """
        Add an artifact to a case.
        
        Args:
            case: Target case
            file_path: Path to artifact file
            artifact_type: Type (email, file, screenshot, log) - auto-detected if None
            
        Returns:
            Artifact metadata
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Auto-detect type
        if artifact_type is None:
            artifact_type = self._detect_artifact_type(file_path)
        
        # Determine destination directory
        type_map = {
            'email': 'emails',
            'file': 'files',
            'malware': 'files',
            'screenshot': 'screenshots',
            'log': 'logs',
        }
        subdir = type_map.get(artifact_type, 'files')
        dest_dir = case.path / 'artifacts' / subdir
        dest_dir.mkdir(parents=True, exist_ok=True)
        
        # Copy file
        dest_path = dest_dir / file_path.name
        shutil.copy2(file_path, dest_path)
        
        # Calculate hashes
        hashes = self._calculate_hashes(dest_path)
        
        # Update case
        case.update_counts()
        case.save()
        
        return {
            'name': file_path.name,
            'type': artifact_type,
            'path': str(dest_path),
            'size': dest_path.stat().st_size,
            'hashes': hashes,
            'added_at': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
        }
    
    def _sanitize_name(self, name: str) -> str:
        """Sanitize case name for use as directory name."""
        # Replace spaces with hyphens
        name = name.replace(' ', '-')
        # Remove invalid characters
        name = ''.join(c for c in name if c.isalnum() or c in '-_')
        return name.lower()
    
    def _detect_artifact_type(self, file_path: Path) -> str:
        """Auto-detect artifact type from file."""
        suffix = file_path.suffix.lower()
        
        if suffix in ['.eml', '.msg']:
            return 'email'
        elif suffix in ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp']:
            return 'screenshot'
        elif suffix in ['.log', '.txt', '.csv'] or 'log' in file_path.name.lower():
            return 'log'
        elif suffix in ['.exe', '.dll', '.scr', '.bat', '.ps1', '.vbs', '.js']:
            return 'malware'
        else:
            return 'file'
    
    def _calculate_hashes(self, file_path: Path) -> Dict[str, str]:
        """Calculate file hashes."""
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            while True:
                data = f.read(65536)
                if not data:
                    break
                md5.update(data)
                sha1.update(data)
                sha256.update(data)
        
        return {
            'md5': md5.hexdigest(),
            'sha1': sha1.hexdigest(),
            'sha256': sha256.hexdigest(),
        }


# Global case manager instance
_case_manager = None


def get_case_manager() -> CaseManager:
    """Get global case manager instance."""
    global _case_manager
    if _case_manager is None:
        _case_manager = CaseManager()
    return _case_manager


def get_active_case() -> Optional[Case]:
    """
    Get the currently active case.
    
    This is the main integration point for other BSOT commands.
    
    Returns:
        Active Case or None
    """
    return get_case_manager().get_active()


def save_output(category: str, filename: str, data: dict) -> bool:
    """
    Save command output to active case.
    
    This should be called by other BSOT commands to auto-save their output.
    
    Args:
        category: Output category (phishing, malware, intel, network, file, logs)
        filename: Output filename (e.g., "analysis-sample.exe.json")
        data: Data to save
        
    Returns:
        True if saved, False if no active case
    """
    case = get_active_case()
    if not case:
        return False
    
    output_dir = case.path / 'outputs' / category
    output_dir.mkdir(parents=True, exist_ok=True)
    
    output_path = output_dir / filename
    output_path.write_text(json.dumps(data, indent=2, default=str))
    
    case.update_counts()
    case.save()
    
    return True


def add_iocs(iocs: List[dict]) -> bool:
    """
    Add IOCs to active case.
    
    Args:
        iocs: List of IOC dictionaries with 'type' and 'value' keys
        
    Returns:
        True if added, False if no active case
    """
    case = get_active_case()
    if not case:
        return False
    
    from .ioc_store import IOCStore
    
    store = IOCStore(case.path / 'iocs.json')
    for ioc in iocs:
        store.add(
            ioc_type=ioc.get('type', 'unknown'),
            value=ioc.get('value', ''),
            source=ioc.get('source', 'auto'),
            confidence=ioc.get('confidence', 'medium'),
            context=ioc.get('context', ''),
        )
    store.save()
    
    case.update_counts()
    case.save()
    
    return True


