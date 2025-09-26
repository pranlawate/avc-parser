"""
SELinux context parsing and semantic analysis.

This module provides classes for parsing SELinux security contexts and
performing semantic analysis of permissions and object classes.
"""


class AvcContext:
    """
    Enhanced SELinux context parsing class based on setroubleshoot's proven approach.

    Parses SELinux security contexts (user:role:type:mls) into structured components
    for enhanced analysis and correlation tracking.
    """

    def __init__(self, context_string: str):
        """
        Initialize AvcContext from a SELinux context string.

        Args:
            context_string (str): SELinux context string (e.g., "system_u:system_r:httpd_t:s0")
        """
        self.user = None
        self.role = None
        self.type = None
        self.mls = None

        if isinstance(context_string, str) and context_string:
            fields = context_string.split(":")
            if len(fields) >= 3:
                self.user = fields[0]
                self.role = fields[1]
                self.type = fields[2]
                if len(fields) > 3:
                    # Handle MLS labels that may contain colons (e.g., s0:c0.c1023)
                    self.mls = ":".join(fields[3:])
                else:
                    # Default MLS level if not present
                    self.mls = "s0"

    def __str__(self) -> str:
        """Return the full context string."""
        if all([self.user, self.role, self.type, self.mls]):
            return f"{self.user}:{self.role}:{self.type}:{self.mls}"
        return ""

    def __repr__(self) -> str:
        """Return a detailed representation."""
        return f"AvcContext(user='{self.user}', role='{self.role}', type='{self.type}', mls='{self.mls}')"

    def __eq__(self, other) -> bool:
        """Compare two AvcContext objects for equality."""
        if not isinstance(other, AvcContext):
            return False
        return (
            self.user == other.user
            and self.role == other.role
            and self.type == other.type
            and self.mls == other.mls
        )

    def __ne__(self, other) -> bool:
        """Compare two AvcContext objects for inequality."""
        return not self.__eq__(other)

    def is_valid(self) -> bool:
        """Check if the context has all required fields."""
        return all([self.user, self.role, self.type, self.mls])

    def get_type_description(self) -> str:
        """
        Get a human-readable description of the SELinux type.

        Returns:
            str: Human-readable description or the type itself if no mapping exists
        """
        # Basic type descriptions for common SELinux types
        type_descriptions = {
            "httpd_t": "Web server process",
            "init_t": "System initialization process",
            "unconfined_t": "Unconfined process",
            "sshd_t": "SSH daemon process",
            "systemd_t": "Systemd service manager",
            "default_t": "Default file context",
            "admin_home_t": "Administrator home directory",
            "user_home_t": "User home directory",
            "tmp_t": "Temporary file",
            "var_t": "Variable data file",
            "etc_t": "Configuration file",
            "bin_t": "System binary",
            "lib_t": "System library",
        }

        return type_descriptions.get(self.type, self.type)


class PermissionSemanticAnalyzer:
    """
    Provides human-readable descriptions and contextual analysis for SELinux permissions.

    Uses static mappings to avoid requiring policy file access while providing
    meaningful insights into denial semantics.
    """

    # Permission descriptions for common SELinux permissions
    PERMISSION_DESCRIPTIONS = {
        # File permissions
        "read": "Read file content",
        "write": "Modify file content",
        "append": "Append to file",
        "execute": "Run executable file",
        "open": "Open file handle",
        "create": "Create new file",
        "unlink": "Delete file",
        "rename": "Rename file",
        "setattr": "Change file attributes",
        "getattr": "Read file attributes",
        "lock": "Lock file for exclusive access",
        "ioctl": "Perform device control operations",
        "map": "Memory map file",
        # Network permissions
        "name_connect": "Connect to network service",
        "name_bind": "Bind to network port",
        "accept": "Accept network connections",
        "listen": "Listen for network connections",
        "recv_msg": "Receive network message",
        "send_msg": "Send network message",
        "node_bind": "Bind to network node",
        # Process permissions
        "transition": "Change security context",
        "signal": "Send signal to process",
        "signull": "Check process existence",
        "sigkill": "Terminate process forcefully",
        "sigstop": "Suspend process",
        "ptrace": "Debug or trace process",
        "getsched": "Get process scheduling info",
        "setsched": "Set process scheduling",
        "share": "Share process memory",
        # Directory permissions
        "search": "Search directory contents",
        "add_name": "Add entry to directory",
        "remove_name": "Remove entry from directory",
        "reparent": "Move directory entry",
        "rmdir": "Remove directory",
        # D-Bus permissions
        "acquire_svc": "Acquire D-Bus service name",
        "send_msg_dbus": "Send D-Bus message",
        # System permissions
        "load": "Load system module",
        "use": "Use system resource",
        "admin": "Perform administrative operation",
        "audit_access": "Access audit logs",
        "audit_control": "Control audit system",
        "setuid": "Change user ID",
        "setgid": "Change group ID",
        # Security permissions
        "enforce": "Enforce security policy",
        "load_policy": "Load security policy",
        "compute_av": "Compute access vector",
        "compute_create": "Compute creation context",
        "compute_member": "Compute member context",
        "check_context": "Validate security context",
    }

    # Object class descriptions
    CLASS_DESCRIPTIONS = {
        "file": "file",
        "dir": "directory",
        "lnk_file": "symbolic link",
        "chr_file": "character device",
        "blk_file": "block device",
        "sock_file": "socket file",
        "fifo_file": "named pipe",
        "tcp_socket": "TCP network socket",
        "udp_socket": "UDP network socket",
        "unix_stream_socket": "Unix stream socket",
        "unix_dgram_socket": "Unix datagram socket",
        "process": "process",
        "dbus": "D-Bus service",
        "capability": "system capability",
        "key": "security key",
        "shm": "shared memory",
        "sem": "semaphore",
        "msg": "message queue",
        "security": "security subsystem",
        "system": "system resource",
    }

    @classmethod
    def get_permission_description(cls, permission: str) -> str:
        """Get human-readable description for a permission."""
        return cls.PERMISSION_DESCRIPTIONS.get(permission, permission)

    @classmethod
    def get_class_description(cls, obj_class: str) -> str:
        """Get human-readable description for an object class."""
        return cls.CLASS_DESCRIPTIONS.get(obj_class, obj_class)

    @classmethod
    def get_contextual_analysis(
        cls,
        permission: str,
        obj_class: str,
        source_context: "AvcContext" = None,
        target_context: "AvcContext" = None,
        process_name: str = None,
    ) -> str:
        """
        Generate contextual analysis based on permission, class, and contexts.

        Args:
            permission: The denied permission
            obj_class: The target object class
            source_context: Source AvcContext object (optional)
            target_context: Target AvcContext object (optional)
            process_name: Actual process name from comm field (optional)

        Returns:
            Human-readable analysis string
        """
        # Get source process description - prioritize actual process name
        source_desc = "Process"
        if process_name:
            # Use actual process name when available
            source_desc = process_name
        elif source_context and source_context.type:
            # Fall back to SELinux type description
            source_desc = source_context.get_type_description()

        # Get target description
        target_desc = cls.get_class_description(obj_class)

        # Generate contextual descriptions based on permission + class combinations
        context_patterns = {
            ("read", "file"): f"{source_desc} attempting to read file content",
            ("write", "file"): f"{source_desc} attempting to modify file content",
            ("execute", "file"): f"{source_desc} attempting to run executable",
            ("open", "file"): f"{source_desc} attempting to open file",
            ("create", "file"): f"{source_desc} attempting to create new file",
            ("unlink", "file"): f"{source_desc} attempting to delete file",
            ("search", "dir"): f"{source_desc} attempting to search directory",
            ("add_name", "dir"): f"{source_desc} attempting to add entry to directory",
            (
                "remove_name",
                "dir",
            ): f"{source_desc} attempting to remove directory entry",
            (
                "name_connect",
                "tcp_socket",
            ): f"{source_desc} attempting to connect to network service",
            (
                "name_bind",
                "tcp_socket",
            ): f"{source_desc} attempting to bind to network port",
            (
                "listen",
                "tcp_socket",
            ): f"{source_desc} attempting to listen for connections",
            ("send_msg", "dbus"): f"{source_desc} attempting to send D-Bus message",
            (
                "acquire_svc",
                "dbus",
            ): f"{source_desc} attempting to acquire D-Bus service",
            (
                "signal",
                "process",
            ): f"{source_desc} attempting to send signal to process",
            ("ptrace", "process"): f"{source_desc} attempting to debug/trace process",
            (
                "transition",
                "process",
            ): f"{source_desc} attempting to change security context",
        }

        # Look for specific pattern match
        pattern_key = (permission, obj_class)
        if pattern_key in context_patterns:
            return context_patterns[pattern_key]

        # Fallback to generic description
        perm_desc = cls.get_permission_description(permission).lower()
        return f"{source_desc} attempting to {perm_desc} on {target_desc}"

    @classmethod
    def get_port_description(cls, port: str) -> str:
        """Get description for common network ports."""
        port_descriptions = {
            "22": "SSH service",
            "80": "HTTP web service",
            "443": "HTTPS web service",
            "3306": "MySQL database",
            "5432": "PostgreSQL database",
            "6379": "Redis cache",
            "8080": "HTTP alternate service",
            "9999": "JBoss management",
            "25": "SMTP mail service",
            "53": "DNS service",
            "993": "IMAPS mail service",
            "995": "POP3S mail service",
        }
        return port_descriptions.get(port, f"port {port}")
