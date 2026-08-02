"""
Case Packager
Package cases for archival or sharing.
"""

import os
import json
import hashlib
import zipfile
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any
from dataclasses import dataclass


@dataclass
class PackageResult:
    """Result of case packaging."""
    package_path: str
    package_size: int
    file_count: int
    sha256: str
    manifest_path: str
    encrypted: bool = False
    error: str = ""
    
    def to_dict(self) -> dict:
        return {
            'package_path': self.package_path,
            'package_size': self.package_size,
            'file_count': self.file_count,
            'sha256': self.sha256,
            'manifest_path': self.manifest_path,
            'encrypted': self.encrypted,
            'error': self.error,
        }


class CasePackager:
    """
    Package cases for archival or sharing.
    """
    
    # File extensions to consider as malware samples
    SAMPLE_EXTENSIONS = {
        '.exe', '.dll', '.scr', '.bat', '.ps1', '.vbs', '.js',
        '.hta', '.com', '.pif', '.msi', '.jar', '.wsf'
    }
    
    def __init__(self, case_path: Path):
        """
        Initialize case packager.
        
        Args:
            case_path: Path to case directory
        """
        self.case_path = Path(case_path)
    
    def package(
        self,
        output_path: Path = None,
        exclude_samples: bool = False,
        password: str = None,
        include_outputs: bool = True,
        compression: int = zipfile.ZIP_DEFLATED
    ) -> PackageResult:
        """
        Create a ZIP package of the case.
        
        Args:
            output_path: Output ZIP path (default: case_name-package.zip)
            exclude_samples: Exclude malware samples (include only hashes)
            password: Optional password for encryption (requires pyzipper)
            include_outputs: Include analysis outputs
            compression: ZIP compression method
            
        Returns:
            PackageResult object
        """
        result = PackageResult(
            package_path="",
            package_size=0,
            file_count=0,
            sha256="",
            manifest_path="",
        )
        
        if not self.case_path.exists():
            result.error = f"Case path not found: {self.case_path}"
            return result
        
        # Determine output path
        if output_path is None:
            case_name = self.case_path.name
            output_path = self.case_path.parent / f"{case_name}-package.zip"
        else:
            output_path = Path(output_path)
        
        # Build file manifest
        manifest = self._build_manifest(exclude_samples, include_outputs)
        
        # Create ZIP
        try:
            if password:
                # Use pyzipper for encryption
                try:
                    import pyzipper
                    result.encrypted = True
                    with pyzipper.AESZipFile(
                        output_path, 'w',
                        compression=pyzipper.ZIP_DEFLATED,
                        encryption=pyzipper.WZ_AES
                    ) as zf:
                        zf.setpassword(password.encode())
                        self._add_files_to_zip(zf, manifest, exclude_samples)
                        # Add manifest
                        manifest_json = json.dumps(manifest, indent=2)
                        zf.writestr('manifest.json', manifest_json)
                except ImportError:
                    result.error = "pyzipper not installed for encryption. Install with: pip install pyzipper"
                    return result
            else:
                with zipfile.ZipFile(output_path, 'w', compression=compression) as zf:
                    self._add_files_to_zip(zf, manifest, exclude_samples)
                    # Add manifest
                    manifest_json = json.dumps(manifest, indent=2)
                    zf.writestr('manifest.json', manifest_json)
            
            result.package_path = str(output_path)
            result.package_size = output_path.stat().st_size
            result.file_count = len(manifest['files'])
            result.sha256 = self._calculate_file_hash(output_path)
            result.manifest_path = str(output_path.parent / 'manifest.json')
            
            # Save manifest separately for reference
            manifest_file = output_path.parent / f"{output_path.stem}-manifest.json"
            manifest_file.write_text(json.dumps(manifest, indent=2))
            result.manifest_path = str(manifest_file)
            
        except Exception as e:
            result.error = str(e)
        
        return result
    
    def _build_manifest(self, exclude_samples: bool, include_outputs: bool) -> dict:
        """Build the package manifest."""
        case_file = self.case_path / 'case.json'
        case_data = {}
        if case_file.exists():
            try:
                case_data = json.loads(case_file.read_text())
            except Exception:
                pass
        
        manifest = {
            'case_id': case_data.get('id', ''),
            'case_name': case_data.get('name', self.case_path.name),
            'packaged_at': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'packaged_by': os.getenv('USER', 'unknown'),
            'exclude_samples': exclude_samples,
            'file_count': 0,
            'files': [],
            'excluded_samples': [],
        }
        
        # Collect files
        for file_path in self.case_path.rglob('*'):
            if not file_path.is_file():
                continue
            
            # Skip __pycache__ and similar
            if '__pycache__' in str(file_path):
                continue
            
            relative_path = file_path.relative_to(self.case_path)
            
            # Check if it's a sample to exclude
            if exclude_samples and self._is_sample(file_path):
                file_hash = self._calculate_file_hash(file_path)
                manifest['excluded_samples'].append({
                    'path': str(relative_path),
                    'sha256': file_hash,
                    'size': file_path.stat().st_size,
                })
                continue
            
            # Check if we should skip outputs
            if not include_outputs and str(relative_path).startswith('outputs/'):
                continue
            
            # Add to manifest
            file_hash = self._calculate_file_hash(file_path)
            manifest['files'].append({
                'path': str(relative_path),
                'sha256': file_hash,
                'size': file_path.stat().st_size,
            })
        
        manifest['file_count'] = len(manifest['files'])
        
        return manifest
    
    def _add_files_to_zip(self, zf, manifest: dict, exclude_samples: bool):
        """Add files to ZIP archive."""
        for file_info in manifest['files']:
            file_path = self.case_path / file_info['path']
            if file_path.exists():
                zf.write(file_path, file_info['path'])
        
        # If excluding samples, add a placeholder with hashes
        if exclude_samples and manifest['excluded_samples']:
            samples_info = "# Excluded Samples\n\n"
            samples_info += "The following files were excluded from this package.\n"
            samples_info += "Only their hashes are included for reference.\n\n"
            
            for sample in manifest['excluded_samples']:
                samples_info += f"## {sample['path']}\n"
                samples_info += f"- SHA256: {sample['sha256']}\n"
                samples_info += f"- Size: {sample['size']} bytes\n\n"
            
            zf.writestr('EXCLUDED_SAMPLES.md', samples_info)
    
    def _is_sample(self, file_path: Path) -> bool:
        """Check if file is likely a malware sample."""
        # Check by extension
        if file_path.suffix.lower() in self.SAMPLE_EXTENSIONS:
            return True
        
        # Check if in files/malware directory
        if 'artifacts/files' in str(file_path) or 'malware' in str(file_path).lower():
            return True
        
        return False
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA256 hash of a file."""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while True:
                data = f.read(65536)
                if not data:
                    break
                sha256.update(data)
        return sha256.hexdigest()
    
    def verify_package(self, package_path: Path, manifest_path: Path = None) -> Dict[str, Any]:
        """
        Verify a package against its manifest.
        
        Args:
            package_path: Path to ZIP package
            manifest_path: Path to manifest file (default: in same directory)
            
        Returns:
            Verification results
        """
        result = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'files_verified': 0,
        }
        
        if manifest_path is None:
            manifest_path = package_path.parent / f"{package_path.stem.replace('-package', '')}-manifest.json"
        
        if not manifest_path.exists():
            result['valid'] = False
            result['errors'].append(f"Manifest not found: {manifest_path}")
            return result
        
        try:
            manifest = json.loads(manifest_path.read_text())
        except Exception as e:
            result['valid'] = False
            result['errors'].append(f"Failed to read manifest: {e}")
            return result
        
        # Extract and verify files
        try:
            with zipfile.ZipFile(package_path, 'r') as zf:
                for file_info in manifest['files']:
                    file_path = file_info['path']
                    expected_hash = file_info['sha256']
                    
                    try:
                        with zf.open(file_path) as f:
                            actual_hash = hashlib.sha256(f.read()).hexdigest()
                        
                        if actual_hash != expected_hash:
                            result['valid'] = False
                            result['errors'].append(f"Hash mismatch: {file_path}")
                        else:
                            result['files_verified'] += 1
                    except KeyError:
                        result['valid'] = False
                        result['errors'].append(f"File missing from package: {file_path}")
        
        except Exception as e:
            result['valid'] = False
            result['errors'].append(f"Failed to read package: {e}")
        
        return result


