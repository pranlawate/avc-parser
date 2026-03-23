# avc-parser

SELinux AVC denial parser and analyzer with extended audit record support.

Parses AVC denial messages from `/var/log/audit/audit.log` with full
support for extended audit records (SYSCALL, PATH, CWD, PROCTITLE).
Provides smart deduplication, severity classification, and multiple
output formats.

## Installation

### Recommended: COPR (Fedora 42/43)

```bash
sudo dnf copr enable pranlawate/selinux-tools
sudo dnf install avc-parser
```

Installs `/usr/bin/avc-parser` with bash/zsh tab completion.

### From GitHub Release

```bash
sudo dnf install https://github.com/pranlawate/avc-parser/releases/download/v1.8.1/avc-parser-1.8.1-1.fc43.noarch.rpm
```

### From source

```bash
git clone https://github.com/pranlawate/avc-parser.git
cd avc-parser
pip install -e .
```

## Usage

```bash
# Parse audit log (auto-detects format)
avc-parser --file /var/log/audit/audit.log

# Brief report format
avc-parser --file /var/log/audit/audit.log --report brief

# JSON output (for tool integration)
avc-parser --file /var/log/audit/audit.log --json

# Filter by process
avc-parser --file /var/log/audit/audit.log --process httpd

# Filter by source context
avc-parser --file /var/log/audit/audit.log --source httpd_t
```

## Part of the SELinux Tool Suite

avc-parser works alongside [sepgen](https://github.com/pranlawate/sepgen)
(policy generator) and [semacro](https://github.com/pranlawate/semacro)
(macro explorer) for a complete SELinux policy development workflow:

```bash
sepgen analyze ./src/ --name myapp    # Generate policy from source
sepgen trace /usr/bin/myapp           # Observe runtime behavior
sepgen refine --name myapp            # Fix denials (uses avc-parser)
semacro which myapp_t target_t read   # Find the right macro
```

Install the complete suite:
```bash
sudo dnf copr enable pranlawate/selinux-tools
sudo dnf install sepgen semacro avc-parser
```

## Documentation

- [Examples & Usage Patterns](docs/EXAMPLES.md)
- [CLI Reference](docs/CLI_REFERENCE.md)
- [Deduplication Algorithm](docs/DEDUPLICATION_ALGORITHM.md)
- [Changelog](docs/CHANGELOG.md)

## License

MIT License — see [LICENSE](LICENSE)

## Author

Pranav Lawate
