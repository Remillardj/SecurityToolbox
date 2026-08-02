"""
File Identifier
Identify file types by magic bytes, not extension.
"""

from pathlib import Path
from dataclasses import dataclass


# Common magic byte signatures
MAGIC_SIGNATURES = {
    # Executables
    b'MZ': ('application/x-dosexec', 'Windows Executable (PE)', ['.exe', '.dll', '.sys']),
    b'\x7fELF': ('application/x-elf', 'Linux Executable (ELF)', ['.elf', '.so', '']),
    b'\xca\xfe\xba\xbe': ('application/x-mach-binary', 'macOS Mach-O (Universal)', ['.app', '']),
    b'\xfe\xed\xfa\xce': ('application/x-mach-binary', 'macOS Mach-O (32-bit)', ['.app', '']),
    b'\xfe\xed\xfa\xcf': ('application/x-mach-binary', 'macOS Mach-O (64-bit)', ['.app', '']),
    b'\xcf\xfa\xed\xfe': ('application/x-mach-binary', 'macOS Mach-O (64-bit, reversed)', ['.app', '']),
    
    # Archives
    b'PK\x03\x04': ('application/zip', 'ZIP Archive', ['.zip', '.jar', '.apk', '.docx', '.xlsx', '.pptx']),
    b'PK\x05\x06': ('application/zip', 'ZIP Archive (empty)', ['.zip']),
    b'PK\x07\x08': ('application/zip', 'ZIP Archive (spanned)', ['.zip']),
    b'\x1f\x8b': ('application/gzip', 'GZIP Archive', ['.gz', '.tgz']),
    b'BZh': ('application/x-bzip2', 'BZIP2 Archive', ['.bz2']),
    b'\xfd7zXZ\x00': ('application/x-xz', 'XZ Archive', ['.xz']),
    b'Rar!\x1a\x07': ('application/x-rar-compressed', 'RAR Archive', ['.rar']),
    b'7z\xbc\xaf\x27\x1c': ('application/x-7z-compressed', '7-Zip Archive', ['.7z']),
    
    # Documents
    b'%PDF': ('application/pdf', 'PDF Document', ['.pdf']),
    b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1': ('application/x-ole-storage', 'Microsoft OLE2 (Office 97-2003)', ['.doc', '.xls', '.ppt', '.msg']),
    b'{\rtf': ('application/rtf', 'Rich Text Format', ['.rtf']),
    
    # Images
    b'\xff\xd8\xff': ('image/jpeg', 'JPEG Image', ['.jpg', '.jpeg']),
    b'\x89PNG\r\n\x1a\n': ('image/png', 'PNG Image', ['.png']),
    b'GIF87a': ('image/gif', 'GIF Image (87a)', ['.gif']),
    b'GIF89a': ('image/gif', 'GIF Image (89a)', ['.gif']),
    b'BM': ('image/bmp', 'BMP Image', ['.bmp']),
    b'RIFF': ('image/webp', 'RIFF Container (WebP/WAV/AVI)', ['.webp', '.wav', '.avi']),
    b'\x00\x00\x01\x00': ('image/x-icon', 'ICO Image', ['.ico']),
    
    # Audio/Video
    b'ID3': ('audio/mpeg', 'MP3 Audio (ID3)', ['.mp3']),
    b'\xff\xfb': ('audio/mpeg', 'MP3 Audio', ['.mp3']),
    b'\xff\xfa': ('audio/mpeg', 'MP3 Audio', ['.mp3']),
    b'fLaC': ('audio/flac', 'FLAC Audio', ['.flac']),
    b'OggS': ('audio/ogg', 'OGG Container', ['.ogg', '.ogv', '.oga']),
    b'\x00\x00\x00\x1cftyp': ('video/mp4', 'MP4 Video', ['.mp4', '.m4v', '.m4a']),
    b'\x00\x00\x00\x20ftyp': ('video/mp4', 'MP4 Video', ['.mp4', '.m4v']),
    
    # Web
    b'<!DOCTYPE html': ('text/html', 'HTML Document', ['.html', '.htm']),
    b'<html': ('text/html', 'HTML Document', ['.html', '.htm']),
    b'<?xml': ('application/xml', 'XML Document', ['.xml']),
    
    # Scripts
    b'#!/bin/bash': ('application/x-shellscript', 'Bash Script', ['.sh']),
    b'#!/bin/sh': ('application/x-shellscript', 'Shell Script', ['.sh']),
    b'#!/usr/bin/env python': ('text/x-python', 'Python Script', ['.py']),
    b'#!/usr/bin/python': ('text/x-python', 'Python Script', ['.py']),
    
    # Data
    b'SQLite format 3': ('application/x-sqlite3', 'SQLite Database', ['.db', '.sqlite', '.sqlite3']),
}


@dataclass
class FileIdentification:
    """File identification result."""
    file_path: str
    file_name: str
    file_size: int
    
    # Identified type
    mime_type: str = "application/octet-stream"
    description: str = "Unknown"
    expected_extensions: list = None
    
    # Extension analysis
    actual_extension: str = ""
    extension_mismatch: bool = False
    mismatch_warning: str = ""
    
    # Magic bytes
    magic_bytes_hex: str = ""
    
    error: str = ""
    
    def __post_init__(self):
        if self.expected_extensions is None:
            self.expected_extensions = []
    
    def to_dict(self) -> dict:
        return {
            'file_path': self.file_path,
            'file_name': self.file_name,
            'file_size': self.file_size,
            'mime_type': self.mime_type,
            'description': self.description,
            'expected_extensions': self.expected_extensions,
            'actual_extension': self.actual_extension,
            'extension_mismatch': self.extension_mismatch,
            'mismatch_warning': self.mismatch_warning,
            'magic_bytes_hex': self.magic_bytes_hex,
            'error': self.error,
        }


class FileIdentifier:
    """
    Identify file types by magic bytes.
    """
    
    def __init__(self, use_libmagic: bool = True):
        """
        Initialize identifier.
        
        Args:
            use_libmagic: Try to use python-magic library if available
        """
        self.use_libmagic = use_libmagic
        self._magic = None
        
        if use_libmagic:
            try:
                import magic
                self._magic = magic.Magic(mime=True)
            except ImportError:
                pass
    
    def identify(self, file_path: str) -> FileIdentification:
        """
        Identify a file's type.
        
        Args:
            file_path: Path to file
            
        Returns:
            FileIdentification result
        """
        path = Path(file_path)
        result = FileIdentification(
            file_path=str(path.absolute()),
            file_name=path.name,
            file_size=0,
            actual_extension=path.suffix.lower()
        )
        
        if not path.exists():
            result.error = "File not found"
            return result
        
        if not path.is_file():
            result.error = "Path is not a file"
            return result
        
        try:
            result.file_size = path.stat().st_size
            
            # Read first 32 bytes for magic detection
            with open(path, 'rb') as f:
                header = f.read(32)
            
            result.magic_bytes_hex = header[:16].hex()
            
            # Try libmagic first
            if self._magic:
                try:
                    mime = self._magic.from_file(str(path))
                    result.mime_type = mime
                    result.description = self._get_description_for_mime(mime)
                    result.expected_extensions = self._get_extensions_for_mime(mime)
                except Exception:
                    pass
            
            # Fall back to manual detection
            if result.mime_type == "application/octet-stream":
                self._detect_by_signature(header, result)
            
            # Check for extension mismatch
            if result.expected_extensions and result.actual_extension:
                if result.actual_extension not in result.expected_extensions:
                    result.extension_mismatch = True
                    result.mismatch_warning = (
                        f"Extension is {result.actual_extension} but content appears to be "
                        f"{result.description} (expected: {', '.join(result.expected_extensions)})"
                    )
            
        except PermissionError:
            result.error = "Permission denied"
        except Exception as e:
            result.error = str(e)
        
        return result
    
    def _detect_by_signature(self, header: bytes, result: FileIdentification):
        """Detect file type by magic bytes."""
        for signature, (mime, desc, exts) in MAGIC_SIGNATURES.items():
            if header.startswith(signature):
                result.mime_type = mime
                result.description = desc
                result.expected_extensions = exts
                return
        
        # Check for text file
        try:
            header.decode('utf-8')
            result.mime_type = "text/plain"
            result.description = "Plain Text"
            result.expected_extensions = ['.txt']
        except UnicodeDecodeError:
            pass
    
    def _get_description_for_mime(self, mime: str) -> str:
        """Get human-readable description for MIME type."""
        descriptions = {
            'application/pdf': 'PDF Document',
            'application/zip': 'ZIP Archive',
            'application/x-dosexec': 'Windows Executable',
            'application/x-elf': 'Linux Executable',
            'application/x-mach-binary': 'macOS Executable',
            'application/x-shellscript': 'Shell Script',
            'text/html': 'HTML Document',
            'text/plain': 'Plain Text',
            'text/x-python': 'Python Script',
            'image/jpeg': 'JPEG Image',
            'image/png': 'PNG Image',
            'image/gif': 'GIF Image',
            'audio/mpeg': 'MP3 Audio',
            'video/mp4': 'MP4 Video',
        }
        return descriptions.get(mime, mime)
    
    def _get_extensions_for_mime(self, mime: str) -> list:
        """Get expected extensions for MIME type."""
        extensions = {
            'application/pdf': ['.pdf'],
            'application/zip': ['.zip', '.jar', '.apk', '.docx', '.xlsx', '.pptx'],
            'application/x-dosexec': ['.exe', '.dll', '.sys'],
            'application/x-elf': ['.elf', '.so', ''],
            'application/x-mach-binary': ['.app', ''],
            'text/html': ['.html', '.htm'],
            'text/plain': ['.txt', '.md', '.log'],
            'text/x-python': ['.py'],
            'image/jpeg': ['.jpg', '.jpeg'],
            'image/png': ['.png'],
            'image/gif': ['.gif'],
            'audio/mpeg': ['.mp3'],
            'video/mp4': ['.mp4', '.m4v'],
        }
        return extensions.get(mime, [])
    
    def is_executable(self, file_path: str) -> bool:
        """Check if file is an executable."""
        result = self.identify(file_path)
        executable_mimes = [
            'application/x-dosexec',
            'application/x-elf',
            'application/x-mach-binary',
            'application/x-shellscript',
        ]
        return result.mime_type in executable_mimes
    
    def is_archive(self, file_path: str) -> bool:
        """Check if file is an archive."""
        result = self.identify(file_path)
        archive_mimes = [
            'application/zip',
            'application/gzip',
            'application/x-bzip2',
            'application/x-xz',
            'application/x-rar-compressed',
            'application/x-7z-compressed',
            'application/x-tar',
        ]
        return result.mime_type in archive_mimes


def identify_file(file_path: str) -> FileIdentification:
    """
    Quick function to identify a file.
    
    Args:
        file_path: Path to file
        
    Returns:
        FileIdentification result
    """
    identifier = FileIdentifier()
    return identifier.identify(file_path)

