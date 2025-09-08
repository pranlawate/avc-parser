"""
Data models for AVC parser.
Contains dataclasses for structured data representation.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class ParsedLog:
    """Represents a parsed AVC log entry.
    
    Attributes:
        datetime_obj: Python datetime object of when the event occurred
        datetime_str: String representation of the timestamp
        timestamp: Unix timestamp of the event
        pid: Process ID that triggered the denial
        comm: Command name of the process
        proctitle: Process title
        exe: Executable path
        cwd: Current working directory
        scontext: Source SELinux context
        tcontext: Target SELinux context
        tclass: SELinux class of the target
        syscall: System call that triggered the denial
        permission: SELinux permission that was denied
        path: Path of the target file/directory
        dest_port: Destination port for network denials
        saddr: Source address for network operations
        permissive: SELinux mode (0=enforcing, 1=permissive)
        additional_fields: Dictionary of any other fields found in the log
    """

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
    
    # SELinux mode
    permissive: Optional[str] = None

    # Additional fields (for flexibility)
    additional_fields: Dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        """Return a detailed string representation for debugging."""
        fields = []
        for key, value in self.__dict__.items():
            if key != "additional_fields" and value is not None:
                fields.append(f"{key}={value!r}")
        if self.additional_fields:
            fields.append(f"additional_fields={self.additional_fields!r}")
        return f"ParsedLog({', '.join(fields)})"

    def validate(self) -> List[str]:
        """Validate the parsed log data and return list of validation errors.
        
        Returns:
            List of validation error messages, empty if all validations pass.
        """
        errors = []

        # Validate timestamp consistency
        if self.datetime_obj and self.timestamp:
            expected_timestamp = self.datetime_obj.timestamp()
            if abs(self.timestamp - expected_timestamp) > 1:  # Allow 1 second tolerance
                errors.append(
                    f"Timestamp mismatch: datetime_obj={self.datetime_obj}, timestamp={self.timestamp}"
                )

        # Validate datetime_str format
        if self.datetime_str:
            try:
                datetime.strptime(self.datetime_str, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                errors.append(f"Invalid datetime_str format: {self.datetime_str}")

        # Validate PID format
        if self.pid and not re.match(r"^\d+$", self.pid):
            errors.append(f"Invalid PID format: {self.pid}")

        # Validate syscall format (can be numeric or named)
        if self.syscall and not (
            re.match(r"^\d+$", self.syscall) or re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", self.syscall)
        ):
            errors.append(f"Invalid syscall format: {self.syscall}")

        # Validate SELinux context format
        if self.scontext and not self._is_valid_selinux_context(self.scontext):
            errors.append(f"Invalid source context format: {self.scontext}")

        if self.tcontext and not self._is_valid_selinux_context(self.tcontext):
            errors.append(f"Invalid target context format: {self.tcontext}")

        # Validate required fields for AVC denial
        if self.permission and not self.tclass:
            errors.append("AVC denial missing target class (tclass)")

        # Validate permissive flag format
        if self.permissive is not None and self.permissive not in ("0", "1"):
            errors.append(f"Invalid permissive flag value: {self.permissive}")

        # Validate network-specific fields
        if self.dest_port is not None:
            if not re.match(r"^\d+$", self.dest_port):
                errors.append(f"Invalid port number: {self.dest_port}")
            else:
                try:
                    port = int(self.dest_port)
                    if port not in range(1, 65536):
                        errors.append(f"Port number out of range (1-65535): {self.dest_port}")
                except ValueError:
                    errors.append(f"Invalid port number: {self.dest_port}")

        return errors
        
    def get_context_type(self, context_field: str) -> Optional[str]:
        """Extract the type component from a SELinux context.
        
        Args:
            context_field: Either 'scontext' or 'tcontext'
            
        Returns:
            The type component of the context, or None if not found
        """
        context = getattr(self, context_field, None)
        if not context:
            return None
        parts = context.split(":")
        if len(parts) >= 3:
            return parts[2]
        return None
        
    def is_network_denial(self) -> bool:
        """Check if this denial is related to network access.
        
        Returns:
            True if this is a network-related denial
        """
        return bool(self.dest_port or self.saddr or self.tclass == "tcp_socket")
        
    def is_file_denial(self) -> bool:
        """Check if this denial is related to file access.
        
        Returns:
            True if this is a file-related denial
        """
        return bool(self.path or self.tclass == "file")
        
    def get_audit2allow_input(self) -> str:
        """Format the denial in a way that can be fed to audit2allow.
        
        Returns:
            A string formatted for audit2allow tool
        """
        parts = ["type=AVC"]
        if self.datetime_obj:
            parts.append(f"msg=audit({self.timestamp}:0)")
        parts.append("avc:  denied")
        if self.permission:
            parts.append(f"{{ {self.permission} }}")
        parts.append("for")
        if self.pid:
            parts.append(f"pid={self.pid}")
        if self.comm:
            parts.append(f'comm="{self.comm}"')
        if self.path:
            parts.append(f'path="{self.path}"')
        if self.dest_port:
            parts.append(f"dest={self.dest_port}")
        if self.scontext:
            parts.append(f"scontext={self.scontext}")
        if self.tcontext:
            parts.append(f"tcontext={self.tcontext}")
        if self.tclass:
            parts.append(f"tclass={self.tclass}")
        return " ".join(parts)

    def _is_valid_selinux_context(self, context: str) -> bool:
        """Validate SELinux context format.
        
        Args:
            context: The SELinux context string to validate
            
        Returns:
            True if the context format is valid
            
        Note:
            A valid SELinux context has the format: user:role:type[:level]
            where level can be complex with ranges like s0-s0:c0.c1023
        """
        # SELinux context format: user:role:type:level
        # Level can be complex with ranges like s0-s0:c0.c1023
        # More permissive pattern to handle complex MLS/MCS levels
        # Handles formats like: system_u:system_r:logrotate_t:s0-s0:c0.c1023
        pattern = r"^[a-zA-Z0-9_]+:[a-zA-Z0-9_]+:[a-zA-Z0-9_]+(:.*)?$"
        return bool(re.match(pattern, context))

    def is_valid(self) -> bool:
        """Check if the parsed log data is valid."""
        return len(self.validate()) == 0

    def to_dict(self, include_none: bool = False) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization.
        
        Args:
            include_none: Whether to include fields with None values
            
        Returns:
            Dictionary representation of the log entry
        """
        result = {}
        for key, value in self.__dict__.items():
            if key == "additional_fields":
                # Only include non-None values from additional_fields unless include_none is True
                if include_none:
                    result.update(value)
                else:
                    result.update({k: v for k, v in value.items() if v is not None})
            elif key == "datetime_obj":
                # Skip datetime_obj as it's not JSON serializable
                continue
            elif value is not None or include_none:
                result[key] = value
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ParsedLog":
        """Create from dictionary."""
        # Extract known fields
        known_fields = {
            "datetime_obj",
            "datetime_str",
            "timestamp",
            "pid",
            "comm",
            "proctitle",
            "exe",
            "cwd",
            "scontext",
            "tcontext",
            "tclass",
            "syscall",
            "permission",
            "path",
            "dest_port",
            "saddr",
            "permissive",
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
    """Represents information about a unique denial.
    
    Attributes:
        log: The parsed AVC log entry
        count: Number of times this denial has occurred
        first_seen_obj: When this denial was first observed
        last_seen_obj: When this denial was last observed
    """

    log: ParsedLog
    count: int
    first_seen_obj: Optional[datetime] = None
    last_seen_obj: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "log": self.log.to_dict(),
            "count": self.count,
            "first_seen": self.first_seen_obj.isoformat() if self.first_seen_obj else None,
            "last_seen": self.last_seen_obj.isoformat() if self.last_seen_obj else None,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DenialInfo":
        """Create from dictionary."""
        log_data = data.get("log", {})
        parsed_log = ParsedLog.from_dict(log_data)

        # Parse datetime fields
        first_seen = None
        last_seen = None

        if data.get("first_seen"):
            first_seen = datetime.fromisoformat(data["first_seen"])
        if data.get("last_seen"):
            last_seen = datetime.fromisoformat(data["last_seen"])

        return cls(
            log=parsed_log,
            count=data.get("count", 1),
            first_seen_obj=first_seen,
            last_seen_obj=last_seen,
        )


@dataclass
class ProcessingStats:
    """Statistics about the processing operation.
    
    Attributes:
        total_log_blocks: Total number of log blocks processed
        unique_denials: Number of unique denials found
        unparsed_types: List of log types that couldn't be parsed
        processing_time: Time taken to process the logs in seconds
    """

    total_log_blocks: int
    unique_denials: int
    unparsed_types: List[str]
    processing_time: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "total_log_blocks": self.total_log_blocks,
            "unique_denials": self.unique_denials,
            "unparsed_types": self.unparsed_types,
            "processing_time": self.processing_time,
        }
