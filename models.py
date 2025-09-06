"""
Data models for AVC parser.
Contains dataclasses for structured data representation.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, Optional, List
import re


@dataclass
class ParsedLog:
    """Represents a parsed AVC log entry."""
    # Timestamp fields
    datetime_obj: Optional[datetime] = None
    datetime_str: Optional[str] = None
    timestamp: Optional[float] = None
    
    # Process information
    pid: Optional[str] = None
    comm: Optional[str] = None
    proctitle: Optional[str] = None
    exe: Optional[str] = None
    cwd: Optional[str] = None
    
    # Security contexts
    scontext: Optional[str] = None
    tcontext: Optional[str] = None
    tclass: Optional[str] = None
    
    # Action details
    syscall: Optional[str] = None
    permission: Optional[str] = None
    
    # Target information
    path: Optional[str] = None
    dest_port: Optional[str] = None
    saddr: Optional[str] = None
    
    # Additional fields (for flexibility)
    additional_fields: Dict[str, Any] = field(default_factory=dict)
    
    def validate(self) -> List[str]:
        """Validate the parsed log data and return list of validation errors."""
        errors = []
        
        # Validate timestamp consistency
        if self.datetime_obj and self.timestamp:
            expected_timestamp = self.datetime_obj.timestamp()
            if abs(self.timestamp - expected_timestamp) > 1:  # Allow 1 second tolerance
                errors.append(f"Timestamp mismatch: datetime_obj={self.datetime_obj}, timestamp={self.timestamp}")
        
        # Validate datetime_str format
        if self.datetime_str:
            try:
                datetime.strptime(self.datetime_str, '%Y-%m-%d %H:%M:%S')
            except ValueError:
                errors.append(f"Invalid datetime_str format: {self.datetime_str}")
        
        # Validate PID format
        if self.pid and not re.match(r'^\d+$', self.pid):
            errors.append(f"Invalid PID format: {self.pid}")
        
        # Validate syscall format (can be numeric or named)
        if self.syscall and not (re.match(r'^\d+$', self.syscall) or re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', self.syscall)):
            errors.append(f"Invalid syscall format: {self.syscall}")
        
        # Validate SELinux context format
        if self.scontext and not self._is_valid_selinux_context(self.scontext):
            errors.append(f"Invalid source context format: {self.scontext}")
        
        if self.tcontext and not self._is_valid_selinux_context(self.tcontext):
            errors.append(f"Invalid target context format: {self.tcontext}")
        
        # Validate required fields for AVC denial
        if self.permission and not self.tclass:
            errors.append("AVC denial missing target class (tclass)")
        
        return errors
    
    def _is_valid_selinux_context(self, context: str) -> bool:
        """Validate SELinux context format."""
        # SELinux context format: user:role:type:level
        # Level can be complex with ranges like s0-s0:c0.c1023
        # More permissive pattern to handle complex MLS/MCS levels
        # Handles formats like: system_u:system_r:logrotate_t:s0-s0:c0.c1023
        pattern = r'^[a-zA-Z0-9_]+:[a-zA-Z0-9_]+:[a-zA-Z0-9_]+(:.*)?$'
        return bool(re.match(pattern, context))
    
    def is_valid(self) -> bool:
        """Check if the parsed log data is valid."""
        return len(self.validate()) == 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {}
        for key, value in self.__dict__.items():
            if key == 'additional_fields':
                result.update(value)
            elif key == 'datetime_obj':
                # Skip datetime_obj as it's not JSON serializable
                continue
            elif value is not None:
                result[key] = value
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ParsedLog':
        """Create from dictionary."""
        # Extract known fields
        known_fields = {
            'datetime_obj', 'datetime_str', 'timestamp', 'pid', 'comm', 
            'proctitle', 'exe', 'cwd', 'scontext', 'tcontext', 'tclass',
            'syscall', 'permission', 'path', 'dest_port', 'saddr'
        }
        
        parsed_log = cls()
        additional_fields = {}
        
        for key, value in data.items():
            if key in known_fields:
                setattr(parsed_log, key, value)
            else:
                additional_fields[key] = value
        
        parsed_log.additional_fields = additional_fields
        return parsed_log


@dataclass
class DenialInfo:
    """Represents information about a unique denial."""
    log: ParsedLog
    count: int
    first_seen_obj: Optional[datetime] = None
    last_seen_obj: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'log': self.log.to_dict(),
            'count': self.count,
            'first_seen': self.first_seen_obj.isoformat() if self.first_seen_obj else None,
            'last_seen': self.last_seen_obj.isoformat() if self.last_seen_obj else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DenialInfo':
        """Create from dictionary."""
        log_data = data.get('log', {})
        parsed_log = ParsedLog.from_dict(log_data)
        
        # Parse datetime fields
        first_seen = None
        last_seen = None
        
        if data.get('first_seen'):
            first_seen = datetime.fromisoformat(data['first_seen'])
        if data.get('last_seen'):
            last_seen = datetime.fromisoformat(data['last_seen'])
        
        return cls(
            log=parsed_log,
            count=data.get('count', 1),
            first_seen_obj=first_seen,
            last_seen_obj=last_seen
        )


@dataclass
class ProcessingStats:
    """Statistics about the processing operation."""
    total_log_blocks: int
    unique_denials: int
    unparsed_types: List[str]
    processing_time: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'total_log_blocks': self.total_log_blocks,
            'unique_denials': self.unique_denials,
            'unparsed_types': self.unparsed_types,
            'processing_time': self.processing_time
        }
