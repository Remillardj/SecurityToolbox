"""
Timeline Manager
Manages investigation timeline for a case.
"""

import json
from pathlib import Path
from datetime import datetime
from typing import List, Optional
from dataclasses import dataclass, asdict


@dataclass
class TimelineEvent:
    """Represents a timeline event."""
    timestamp: str
    event: str
    source: str  # analyst, phishing_analysis, malware_analysis, etc.
    artifact: Optional[str] = None  # Related artifact path
    details: Optional[dict] = None
    
    def to_dict(self) -> dict:
        result = {
            'timestamp': self.timestamp,
            'event': self.event,
            'source': self.source,
        }
        if self.artifact:
            result['artifact'] = self.artifact
        if self.details:
            result['details'] = self.details
        return result
    
    @classmethod
    def from_dict(cls, data: dict) -> 'TimelineEvent':
        return cls(
            timestamp=data.get('timestamp', ''),
            event=data.get('event', ''),
            source=data.get('source', 'unknown'),
            artifact=data.get('artifact'),
            details=data.get('details'),
        )


class TimelineManager:
    """
    Manages the investigation timeline for a case.
    """
    
    def __init__(self, timeline_file: Path):
        """
        Initialize timeline manager.
        
        Args:
            timeline_file: Path to timeline.json file
        """
        self.timeline_file = Path(timeline_file)
        self.events: List[TimelineEvent] = []
        
        self._load()
    
    def _load(self):
        """Load timeline from file."""
        if self.timeline_file.exists():
            try:
                data = json.loads(self.timeline_file.read_text())
                if isinstance(data, list):
                    for item in data:
                        self.events.append(TimelineEvent.from_dict(item))
            except Exception:
                pass
    
    def save(self):
        """Save timeline to file."""
        data = [event.to_dict() for event in self.events]
        self.timeline_file.write_text(json.dumps(data, indent=2))
    
    def add(
        self,
        event: str,
        timestamp: str = None,
        source: str = 'analyst',
        artifact: str = None,
        details: dict = None
    ) -> TimelineEvent:
        """
        Add an event to the timeline.
        
        Args:
            event: Event description
            timestamp: Event timestamp (ISO format, default: now)
            source: Event source
            artifact: Related artifact path
            details: Additional details
            
        Returns:
            Created TimelineEvent
        """
        if timestamp is None:
            timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        else:
            # Try to normalize timestamp
            timestamp = self._normalize_timestamp(timestamp)
        
        timeline_event = TimelineEvent(
            timestamp=timestamp,
            event=event,
            source=source,
            artifact=artifact,
            details=details,
        )
        
        self.events.append(timeline_event)
        
        # Sort by timestamp
        self._sort()
        
        return timeline_event
    
    def get_all(self) -> List[TimelineEvent]:
        """Get all events sorted by timestamp."""
        return self.events.copy()
    
    def get_by_source(self, source: str) -> List[TimelineEvent]:
        """Get events from a specific source."""
        return [e for e in self.events if e.source == source]
    
    def get_range(self, start: str, end: str) -> List[TimelineEvent]:
        """Get events within a time range."""
        return [
            e for e in self.events
            if start <= e.timestamp <= end
        ]
    
    def count(self) -> int:
        """Get total event count."""
        return len(self.events)
    
    def clear(self):
        """Clear all events."""
        self.events = []
    
    def to_markdown(self) -> str:
        """Export timeline as markdown table."""
        lines = [
            '# Investigation Timeline',
            '',
            '| Time | Event | Source |',
            '|------|-------|--------|',
        ]
        
        for event in self.events:
            # Format timestamp for display
            try:
                dt = datetime.fromisoformat(event.timestamp.replace('Z', '+00:00'))
                time_str = dt.strftime('%Y-%m-%d %H:%M:%S')
            except Exception:
                time_str = event.timestamp
            
            lines.append(f'| {time_str} | {event.event} | {event.source} |')
        
        return '\n'.join(lines)
    
    def to_csv(self) -> str:
        """Export timeline as CSV."""
        lines = ['timestamp,event,source,artifact']
        
        for event in self.events:
            event_text = event.event.replace('"', '""')
            artifact = event.artifact or ''
            lines.append(f'{event.timestamp},"{event_text}",{event.source},"{artifact}"')
        
        return '\n'.join(lines)
    
    def to_ascii(self, max_width: int = 80) -> str:
        """Generate ASCII timeline visualization."""
        if not self.events:
            return "No timeline events."
        
        lines = []
        for i, event in enumerate(self.events):
            # Format timestamp
            try:
                dt = datetime.fromisoformat(event.timestamp.replace('Z', '+00:00'))
                time_str = dt.strftime('%Y-%m-%d %H:%M')
            except Exception:
                time_str = event.timestamp[:16]
            
            # Truncate event text if needed
            event_text = event.event
            max_event_len = max_width - 30
            if len(event_text) > max_event_len:
                event_text = event_text[:max_event_len - 3] + '...'
            
            # Build line
            if i == 0:
                lines.append(f"  ┌─ {time_str}")
            else:
                lines.append(f"  │")
                lines.append(f"  ├─ {time_str}")
            
            lines.append(f"  │  └── {event_text}")
            lines.append(f"  │       ({event.source})")
        
        lines.append("  │")
        lines.append("  └─ [End of timeline]")
        
        return '\n'.join(lines)
    
    def _sort(self):
        """Sort events by timestamp."""
        self.events.sort(key=lambda e: e.timestamp)
    
    def _normalize_timestamp(self, timestamp: str) -> str:
        """Normalize timestamp to ISO format."""
        # Common formats to try
        formats = [
            '%Y-%m-%dT%H:%M:%SZ',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%d %H:%M',
            '%Y-%m-%d',
            '%m/%d/%Y %H:%M:%S',
            '%m/%d/%Y %H:%M',
            '%m/%d/%Y',
        ]
        
        for fmt in formats:
            try:
                dt = datetime.strptime(timestamp.strip(), fmt)
                return dt.strftime('%Y-%m-%dT%H:%M:%SZ')
            except ValueError:
                continue
        
        # Return as-is if parsing fails
        return timestamp


class NotesManager:
    """
    Manages investigation notes for a case.
    """
    
    def __init__(self, notes_file: Path):
        """
        Initialize notes manager.
        
        Args:
            notes_file: Path to notes.md file
        """
        self.notes_file = Path(notes_file)
        
        if not self.notes_file.exists():
            self.notes_file.write_text('# Investigation Notes\n\n')
    
    def add(self, text: str, timestamp: str = None):
        """
        Add a note.
        
        Args:
            text: Note text
            timestamp: Note timestamp (default: now)
        """
        if timestamp is None:
            timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        
        content = self.notes_file.read_text()
        
        note_entry = f"\n## {timestamp}\n{text}\n"
        
        content += note_entry
        self.notes_file.write_text(content)
    
    def get_all(self) -> str:
        """Get all notes as markdown."""
        return self.notes_file.read_text()
    
    def get_entries(self) -> List[dict]:
        """Parse notes into structured entries."""
        content = self.notes_file.read_text()
        entries = []
        
        current_timestamp = None
        current_text = []
        
        for line in content.split('\n'):
            if line.startswith('## '):
                # Save previous entry
                if current_timestamp and current_text:
                    entries.append({
                        'timestamp': current_timestamp,
                        'text': '\n'.join(current_text).strip(),
                    })
                
                # Start new entry
                current_timestamp = line[3:].strip()
                current_text = []
            elif not line.startswith('# '):
                current_text.append(line)
        
        # Save last entry
        if current_timestamp and current_text:
            entries.append({
                'timestamp': current_timestamp,
                'text': '\n'.join(current_text).strip(),
            })
        
        return entries
    
    def count(self) -> int:
        """Get note count."""
        return len(self.get_entries())
    
    def clear(self):
        """Clear all notes."""
        self.notes_file.write_text('# Investigation Notes\n\n')


