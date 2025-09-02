# SELinux AVC Log Parser

A simple, standalone Python script to parse raw SELinux audit logs into a clean, human-readable format using the `rich` library for beautiful terminal output.

## Features

-   Parses multi-line audit log blocks containing `AVC`, `SYSCALL`, `CWD`, `PATH`, `PROCTITLE`, and `SOCKADDR` records.
-   Extracts key information like process name, PID, contexts, permissions, and paths.
-   Handles both hex-encoded and plain-text `proctitle` fields.
-   Accepts input from either a file or an interactive prompt.
-   Outputs a clean, formatted, and color-coded summary to the terminal.

## Prerequisites

-   Python 3.6+
-   Rich library: `pip install rich`

## Usage

1.  **Clone the Repository**:
    ```shell
    git clone [https://github.com/pranlawate/avc_parser.git](https://github.com/pranlawate/avc_parser.git)
    cd avc_parser
    ```

2.  **Install Dependencies**:
    ```shell
    pip install rich
    ```

3.  **Run the script in one of two ways**:

    **Option A: From a File**
    Provide the path to a log file using the `-f` or `--file` argument.
    ```shell
    python parse_avc.py --file /path/to/your/audit.log
    ```

    **Option B: Interactively**
    Run the script with no arguments to be prompted to paste the log directly into the terminal.
    ```shell
    python parse_avc.py
    ```
    (After pasting, press `Ctrl+D` on Linux/macOS or `Ctrl+Z`+`Enter` on Windows to submit).

## Example Output

For the provided log, the script will produce a detailed summary like this:
1. A standard AVC log directly pasted into prompt:
```shell
$ ../selinux-ai-tool/venv/bin/python parse_avc.py
📋 Please paste your SELinux AVC denial log below and press Ctrl+D (or Ctrl+Z on Windows) when done:
type=SYSCALL msg=audit(08/31/2025 22:56:00.345:403): arch=x86_64 syscall=listen success=no exit=EACCES comm="httpd" exe="/usr/sbin/httpd" subj=unconfined_u:unconfined_r:unconfined_t:s0 key=(null)
type=AVC msg=audit(08/31/2025 22:56:00.345:403): avc: denied  { name_bind } for  pid=8765 comm="httpd" src=80 scontext=unconfined_u:unconfined_r:unconfined_t:s0 tcontext=system_u:object_r:http_port_t:s0 tclass=tcp_socket permissive=0

Found 1 log blocks(s). Displaying unique denials...
────────────────────────────────────────────────────────── Parsed Log Summary ──────────────────────────────────────────────────────────
─────────────────────────────────────────────────────────── Unique Denial #1 ───────────────────────────────────────────────────────────
  Executable:/usr/sbin/httpd
  Process Name:httpd
  Process ID (PID):8765
  Source Context:unconfined_u:unconfined_r:unconfined_t:s0
-----------------------------------
  Action:Denied
  Syscall:listen
  Permission:name_bind
-----------------------------------
  Target Class:tcp_socket
  Target Context:system_u:object_r:http_port_t:s0
-----------------------------------

Analysis Complete: Processed 1 log blocks and found 1 unique denials.
```
2. Standard log with httpd denial in a file on filecontext mismatch:
```shell
$ cat standard_AVC.log
----
type=SYSCALL msg=audit(09/01/2025 00:41:00.123:501): arch=x86_64 syscall=openat success=no exit=EACCES a0=0xffffff9c a1=0x7ffc1a3b4d80 a2=0x0 a3=0x0 items=1 ppid=1 pid=2345 auid=4294967295 uid=48 gid=48 euid=48 suid=48 fsuid=48 egid=48 sgid=48 fsgid=48 tty=(none) ses=4294967295 comm="httpd" exe="/usr/sbin/httpd" subj=system_u:system_r:httpd_t:s0 key=(null)
type=CWD msg=audit(09/01/2025 00:41:00.123:501): cwd="/"
type=PATH msg=audit(09/01/2025 00:41:00.123:501): item=0 name="/var/www/html/test.html" inode=56789 dev=fd:00 mode=0100644 ouid=0 ogid=0 rdev=00:00 obj=unconfined_u:object_r:default_t:s0 objtype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=AVC msg=audit(09/01/2025 00:41:00.123:501): avc: denied  { read } for  pid=2345 comm="httpd" path="/var/www/html/test.html" dev=vda1 ino=56789 scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file permissive=0
----

$ python parse_avc.py -f  standard_AVC.log 

Found 1 log blocks(s). Displaying unique denials...
────────────────────────────────────────────────────────── Parsed Log Summary ──────────────────────────────────────────────────────────
─────────────────────────────────────────────────────────── Unique Denial #1 ───────────────────────────────────────────────────────────
  Executable:/usr/sbin/httpd
  Process Name:httpd
  Process ID (PID):2345
  Working Dir (CWD):/
  Source Context:system_u:system_r:httpd_t:s0
-----------------------------------
  Action:Denied
  Syscall:openat
  Permission:read
-----------------------------------
  Target Path:/var/www/html/test.html
  Target Class:file
  Target Context:unconfined_u:object_r:default_t:s0
-----------------------------------

Analysis Complete: Processed 1 log blocks and found 1 unique denials.
```

3. A standard network AVC denial log in a file with socket information:
```shell
$ cat network_AVC.log
type=PROCTITLE msg=audit(07/29/2025 09:52:29.237:87712186) : proctitle=2F7573722F7362696E2F6874747064202D44464F524547524F554E44
type=SOCKADDR msg=audit(07/29/2025 09:52:29.237:87712186) : saddr={ saddr_fam=inet laddr=10.233.237.96 lport=9999 }
type=SYSCALL msg=audit(07/29/2025 09:52:29.237:87712186) : arch=x86_64 syscall=connect success=no exit=EACCES comm=httpd exe=/usr/sbin/httpd subj=system_u:system_r:httpd_t:s0
type=AVC msg=audit(07/29/2025 09:52:29.237:87712186) : avc:  denied  { name_connect } for  pid=4182412 comm=httpd dest=9999 scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:jboss_management_port_t:s0 tclass=tcp_socket

$ python parse_avc.py -f network_AVC.log 

Found 1 log blocks(s). Displaying unique denials...
────────────────────────────────────────────────────────── Parsed Log Summary ──────────────────────────────────────────────────────────
─────────────────────────────────────────────────────────── Unique Denial #1 ───────────────────────────────────────────────────────────
  Process Title:/usr/sbin/httpd -DFOREGROUND
  Process ID (PID):4182412
  Source Context:system_u:system_r:httpd_t:s0
-----------------------------------
  Action:Denied
  Syscall:connect
  Permission:name_connect
-----------------------------------
  Target Port:9999
  Socket Address:saddr_fam=inet laddr=10.233.237.96 lport=9999
  Target Class:tcp_socket
  Target Context:system_u:object_r:jboss_management_port_t:s0
-----------------------------------

Analysis Complete: Processed 1 log blocks and found 1 unique denials.
```
4. For a log with multiline AVC denials, a smaller version of realistic logs found in audit.log in real world issues.
```shell
$ cat ../testfiles/multi_AVC.log 
----
type=SYSCALL msg=audit(...): arch=x86_64 syscall=openat comm="httpd" exe="/usr/sbin/httpd" subj=system_u:system_r:httpd_t:s0
type=AVC msg=audit(...): avc: denied  { read } for  pid=1234 comm="httpd" path="/var/www/html/file1.html" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file
----
type=SYSCALL msg=audit(...): arch=x86_64 syscall=connect comm="httpd" exe="/usr/sbin/httpd" subj=system_u:system_r:httpd_t:s0
type=AVC msg=audit(...): avc: denied  { name_connect } for  pid=1235 comm="httpd" dest=5432 scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:postgresql_port_t:s0 tclass=tcp_socket
----
type=SYSCALL msg=audit(...): arch=x86_64 syscall=openat comm="httpd" exe="/usr/sbin/httpd" subj=system_u:system_r:httpd_t:s0
type=AVC msg=audit(...): avc: denied  { read } for  pid=1236 comm="httpd" path="/var/www/html/file2.html" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file

$ python parse_avc.py -f ../testfiles/multi_AVC.log
────────────────────────────────────────────────────────── Skipping duplicate ──────────────────────────────────────────────────────────

Found 3 log blocks(s). Displaying unique denials...
────────────────────────────────────────────────────────── Parsed Log Summary ──────────────────────────────────────────────────────────
─────────────────────────────────────────────────────────── Unique Denial #1 ───────────────────────────────────────────────────────────
  Executable:/usr/sbin/httpd
  Process Name:httpd
  Process ID (PID):1234
  Source Context:system_u:system_r:httpd_t:s0
-----------------------------------
  Action:Denied
  Syscall:openat
  Permission:read
-----------------------------------
  Target Path:/var/www/html/file1.html
  Target Class:file
  Target Context:unconfined_u:object_r:default_t:s0
-----------------------------------
─────────────────────────────────────────────────────────── Unique Denial #2 ───────────────────────────────────────────────────────────
  Executable:/usr/sbin/httpd
  Process Name:httpd
  Process ID (PID):1235
  Source Context:system_u:system_r:httpd_t:s0
-----------------------------------
  Action:Denied
  Syscall:connect
  Permission:name_connect
-----------------------------------
  Target Port:5432
  Target Class:tcp_socket
  Target Context:system_u:object_r:postgresql_port_t:s0
-----------------------------------

Analysis Complete: Processed 3 log blocks and found 2 unique denials.
```
