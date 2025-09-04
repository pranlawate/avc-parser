# SELinux AVC Log Parser

A simple, standalone Python script to parse raw or pre-processed SELinux audit logs into a clean, human-readable format.

## Features

-   Parses multi-line AVC audit log blocks pre-processed by ausearch separated by '----', containing `AVC`, `SYSCALL`, `CWD`, `PATH`, `PROCTITLE`, and `SOCKADDR` records.
-   Can directrly process raw `audit.log` files by internally using `ausearch`.
-   Extracts key information like process name, PID, contexts, permissions, and paths.
-   **De-duplicates denials** and timestamps for the **first and last time** a unique denial from a large log file.
-   Identifies and lists any unparsed record types to aid in future development.
-   Accepts input from raw log file, a pre-processed log file, or an interactive prompt.
-   Outputs a clean, formatted, and color-coded summary using 'rich' library or a structured **JSON** format.

## Prerequisites

-   Python 3.6+
-   Python Rich library
-   `audit` package (for `ausearch`): Usually is preinstalled.

## Usage

1.  **Clone the Repository**:
    * Using HTTPS
    ```shell
    git clone https://github.com/pranlawate/avc_parser.git
    ```
    * Using SSH 
    ```shell
    git clone git@github.com:pranlawate/avc-parser.git
    ```

2.  **Install Dependencies**:
    ```shell
    pip install rich
    sudo dnf install audit (If needed)
    ```

3.  **You can run the script in one of the three ways:**
    ### **Option A: From a RAW Audit File**
    This would be most used option for parsing the system audit logs as it is. The script will run `ausearch` internally for you.
    ```shell
    python parse_avc.py --raw-file /path/to/file/audit.log
    ```
    (Short argument -rf)

    ### **Option B: From a Pre-processed AVC File**
    Useful when you already have created a AVC log file using ausearch. 
    ```shell
    # First, create the file:
    ausearch -m AVC -ts recent > AVC.log

    # Then, run the parser on it:
    python parse_avc.py --avc-file[-af] AVC.log
    ```
    (Short arugment -af)
 
    ### Option C: Interactively
    Run the script with no arguments to be prompted to paste pre-formatted(---- delimited) log directly into the terminal. Useful for a checking a few logs on the go.
    ```shell
    python parse_avc.py
    ```
    (After pasting, press `Ctrl+D` on Linux/macOS or `Ctrl+Z`+`Enter` on Windows to submit).

    ### Option D: JSON Output(Recent addition)
    Add the `--json` flag to any of the above commands to get a json block that can be used in multitude of ML/AI applications
    ```shell
    python parse_avc.py -rf /var/log/audit/audit.log --json

## Example Output

For the provided log, the script will produce a detailed summary like this:
1. A standard AVC log directly pasted into prompt:
```shell
$ python parse_avc.py 
📋 Please paste your SELinux AVC denial log below and press Ctrl+D when done:
type=AVC msg=audit(1725300000.101:123): avc: denied { read } for pid=1234 comm="httpd" path="/var/www/html/file1.html" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file

Found 1 AVC events. Displaying 1 unique denials...
────────────────────────────── Parsed Log Summary ──────────────────────────────
────────── Unique Denial #1 (1 occurrences, last seen 1 year(s) ago) ───────────
  Timestamp:2024-09-02 23:30:00
  Process Name:httpd
  Process ID (PID):1234
  Source Context:system_u:system_r:httpd_t:s0
-----------------------------------
  Action:Denied
  Permission:read
-----------------------------------
  Target Path:/var/www/html/file1.html
  Target Class:file
  Target Context:unconfined_u:object_r:default_t:s0
-----------------------------------

Analysis Complete: Processed 1 log blocks and found 1 unique denials.
```
2. Standard log with httpd denial in a file on filecontext mismatch with unix timestamp:
```shell
$ cat file_context_AVC.log
----
type=SYSCALL msg=audit(1725482881.101:501): arch=x86_64 syscall=openat success=no exit=EACCES comm="httpd" exe="/usr/sbin/httpd" subj=system_u:system_r:httpd_t:s0 key=(null)
type=CWD msg=audit(1725482881.101:501): cwd="/"
type=PATH msg=audit(1725482881.101:501): item=0 name="/var/www/html/index.html" inode=12345 dev=vda1 mode=0100644 ouid=0 ogid=0 rdev=00:00 obj=unconfined_u:object_r:default_t:s0 objtype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=AVC msg=audit(1725482881.101:501): avc: denied  { read } for  pid=1234 comm="httpd" path="/var/www/html/index.html" dev="vda1" ino=12345 scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file permissive=0
----

$ python parse_avc.py -af  standard_AVC.log
Pre-processed AVC file provided: 'file_context_AVC.log'

Found 1 AVC events. Displaying 1 unique denials...
────────────────────────────── Parsed Log Summary ──────────────────────────────
───────── Unique Denial #1 (1 occurrences, last seen 12 month(s) ago) ──────────
  Timestamp:2024-09-05 02:18:01
  Executable:/usr/sbin/httpd
  Process Name:httpd
  Process ID (PID):1234
  Working Dir (CWD):/
  Source Context:system_u:system_r:httpd_t:s0
-----------------------------------
  Action:Denied
  Syscall:openat
  Permission:read
-----------------------------------
  Target Path:/var/www/html/index.html
  Target Class:file
  Target Context:unconfined_u:object_r:default_t:s0
-----------------------------------

Analysis Complete: Processed 1 log blocks and found 1 unique denials.
```

3. A standard network AVC denial log in a file with socket information and hex-encoded proctitle:
```shell
$ cat network_AVC.log
type=PROCTITLE msg=audit(07/29/2025 09:52:29.237:87712186) : proctitle=2F7573722F7362696E2F6874747064202D44464F524547524F554E44
type=SOCKADDR msg=audit(07/29/2025 09:52:29.237:87712186) : saddr={ saddr_fam=inet laddr=10.233.237.96 lport=9999 }
type=SYSCALL msg=audit(07/29/2025 09:52:29.237:87712186) : arch=x86_64 syscall=connect success=no exit=EACCES comm=httpd exe=/usr/sbin/httpd subj=system_u:system_r:httpd_t:s0
type=AVC msg=audit(07/29/2025 09:52:29.237:87712186) : avc:  denied  { name_connect } for  pid=4182412 comm=httpd dest=9999 scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:jboss_management_port_t:s0 tclass=tcp_socket

$ python parse_avc.py -rf network_AVC.log 
Pre-processed AVC file provided: 'network_AVC.log'

Found 1 AVC events. Displaying 1 unique denials...
────────────────────────────── Parsed Log Summary ──────────────────────────────
────────── Unique Denial #1 (1 occurrences, last seen 1 month(s) ago) ──────────
  Timestamp:2025-07-29 09:52:29
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
4. For a log with multiline AVC denials, that includes hex enconded proctitle
```shell
$ cat ../testfiles/multi_AVC.log 
----
type=PROCTITLE msg=audit(09/04/2025 18:19:00.303:503): proctitle=2F7573722F7362696E2F6874747064202D44464F524547524F554E44
type=SYSCALL msg=audit(09/04/2025 18:19:00.303:503): arch=x86_64 syscall=openat success=no exit=EACCES comm="httpd" exe="/usr/sbin/httpd" subj=system_u:system_r:httpd_t:s0
type=PATH msg=audit(09/04/2025 18:19:00.303:503): item=0 name="/var/www/html/file1.html" obj=unconfined_u:object_r:default_t:s0
type=AVC msg=audit(09/04/2025 18:19:00.303:503): avc: denied  { read } for  pid=1234 comm="httpd" path="/var/www/html/file1.html" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file
----
type=USER_ACCT msg=audit(09/04/2025 18:19:05.305:504): acct="root" exe="/usr/sbin/crond"
----
type=SYSCALL msg=audit(09/04/2025 18:19:20.404:505): arch=x86_64 syscall=connect success=no exit=EACCES comm="httpd" exe="/usr/sbin/httpd" subj=system_u:system_r:httpd_t:s0
type=AVC msg=audit(09/04/2025 18:19:20.404:505): avc: denied  { name_connect } for  pid=5678 comm="httpd" dest=5432 scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:postgresql_port_t:s0 tclass=tcp_socket
----
type=SYSCALL msg=audit(09/04/2025 18:19:30.505:506): arch=x86_64 syscall=openat success=no exit=EACCES comm="httpd" exe="/usr/sbin/httpd" subj=system_u:system_r:httpd_t:s0
type=AVC msg=audit(09/04/2025 18:19:30.505:506): avc: denied  { read } for  pid=1235 comm="httpd" path="/var/www/html/file2.html" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:default_t:s0 tclass=file
----

$ python parse_avc.py -af ../testfiles/multi_AVC.log
Pre-processed AVC file provided: 'multi_AVC.log'

Found 4 AVC events. Displaying 2 unique denials...
────────────────────────────── Parsed Log Summary ──────────────────────────────
────────── Unique Denial #1 (2 occurrences, last seen 5 hour(s) ago) ───────────
  Timestamp:2025-09-04 18:19:00
  Process Title:/usr/sbin/httpd -DFOREGROUND
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
────────────────────────────────────────────────────────────────────────────────
────────── Unique Denial #2 (1 occurrences, last seen 5 hour(s) ago) ───────────
  Timestamp:2025-09-04 18:19:20
  Executable:/usr/sbin/httpd
  Process Name:httpd
  Process ID (PID):5678
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

Analysis Complete: Processed 4 log blocks and found 2 unique denials.

Note: The following record types were found in the log but are not currently 
parsed:
  USER_ACCT
```
5. For an actual RAW audit log that has 74 AVCs about only 2 unique recurring denials.(Something we usually see for unconfined_t)
```shell
$ sudo ausearch -m AVC -if audit.log | grep AVC -c
74
$ sudo ausearch -m AVC -if audit.log | grep AVC | grep pulpcore-worker -c
74
$ sudo ausearch -m AVC -if audit.log | grep AVC | grep pulpcore | awk '{print $1=$2=$8=$9="",$0}' | sort -u
   avc: denied { read }   comm="pulpcore-worker" scontext=system_u:system_r:pulpcore_t:s0 tcontext=system_u:system_r:unconfined_service_t:s0 tclass=key permissive=1
   avc: denied { view }   comm="pulpcore-worker" scontext=system_u:system_r:pulpcore_t:s0 tcontext=system_u:system_r:unconfined_service_t:s0 tclass=key permissive=1

$ python parse_avc.py -rf audit.log
Raw file input provided. Running ausearch on 'audit.log'...

Found 74 AVC events. Displaying 2 unique denials...
────────────────────────────── Parsed Log Summary ──────────────────────────────
───────── Unique Denial #1 (37 occurrences, last seen 1 month(s) ago) ──────────
  Timestamp:2025-07-14 02:30:53
  Process Title:/usr/bin/python3.11
  Process ID (PID):1020588
  Source Context:system_u:system_r:pulpcore_t:s0
-----------------------------------
  Action:Denied
  Syscall:keyctl
  Permission:read
-----------------------------------
  Target Class:key
  Target Context:system_u:system_r:unconfined_service_t:s0
-----------------------------------
────────────────────────────────────────────────────────────────────────────────
───────── Unique Denial #2 (37 occurrences, last seen 1 month(s) ago) ──────────
  Timestamp:2025-07-14 02:30:53
  Process Title:/usr/bin/python3.11
  Process ID (PID):1020588
  Source Context:system_u:system_r:pulpcore_t:s0
-----------------------------------
  Action:Denied
  Syscall:keyctl
  Permission:view
-----------------------------------
  Target Class:key
  Target Context:system_u:system_r:unconfined_service_t:s0
-----------------------------------

Analysis Complete: Processed 74 log blocks and found 2 unique denials.
```
