Name:           avc-parser
Version:        1.8.1
Release:        1%{?dist}
Summary:        SELinux AVC denial parser and analyzer with extended audit record support

License:        MIT
URL:            https://github.com/pranlawate/avc-parser
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch
Requires:       python3 >= 3.8
Requires:       python3-rich
Requires:       policycoreutils

%description
Parses SELinux AVC denial messages from audit logs with extended audit
record support (SYSCALL, PATH, CWD, PROCTITLE). Provides structured
analysis with smart deduplication, severity classification, and multiple
output formats including JSON, brief, and sealert-style reports.

Part of the SELinux policy development tool suite alongside sepgen
(policy generator) and semacro (macro explorer).

%prep
%autosetup

%install
mkdir -p %{buildroot}%{_libexecdir}/avc-parser
install -Dm755 parse_avc.py %{buildroot}%{_libexecdir}/avc-parser/parse_avc.py

for dir in config detectors formatters selinux utils validators; do
    if [ -d "$dir" ]; then
        cp -r "$dir" %{buildroot}%{_libexecdir}/avc-parser/
    fi
done

mkdir -p %{buildroot}%{_bindir}
cat > %{buildroot}%{_bindir}/avc-parser << 'WRAPPER'
#!/bin/bash
exec python3 %{_libexecdir}/avc-parser/parse_avc.py "$@"
WRAPPER
chmod 755 %{buildroot}%{_bindir}/avc-parser

install -Dm644 avc-parser.1 %{buildroot}%{_mandir}/man1/avc-parser.1
install -Dm644 completions/avc-parser.bash \
    %{buildroot}%{_datadir}/bash-completion/completions/avc-parser
install -Dm644 completions/avc-parser.zsh \
    %{buildroot}%{_datadir}/zsh/site-functions/_avc-parser

%files
%license LICENSE
%doc README.md
%{_bindir}/avc-parser
%{_libexecdir}/avc-parser/
%{_mandir}/man1/avc-parser.1*
%{_datadir}/bash-completion/completions/avc-parser
%{_datadir}/zsh/site-functions/_avc-parser

%changelog
* Sun Mar 22 2026 Pranav Lawate <pran.lawate@gmail.com> - 1.8.1-1
- Initial RPM packaging
- Extended audit record support (SYSCALL, PATH, CWD, PROCTITLE)
- JSON output format for tool integration
- Smart deduplication and severity classification
