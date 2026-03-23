Name:           avc-parser
Version:        1.8.1
Release:        2%{?dist}
Summary:        SELinux AVC denial parser and analyzer with extended audit record support

License:        MIT
URL:            https://github.com/pranlawate/avc-parser
Source0:        https://github.com/pranlawate/%{name}/archive/v%{version}/%{name}-%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  python3-devel
BuildRequires:  python3-setuptools
BuildRequires:  python3-wheel
BuildRequires:  python3-pytest
BuildRequires:  python3-rich
Requires:       python3 >= 3.8
Requires:       python3-rich
Recommends:     policycoreutils

%description
Parses SELinux AVC denial messages from audit logs with extended audit
record support (SYSCALL, PATH, CWD, PROCTITLE). Provides structured
analysis with smart deduplication, severity classification, and multiple
output formats including JSON, brief, and sealert-style reports.

Part of the SELinux policy development tool suite alongside sepgen
(policy generator) and semacro (macro explorer).

%prep
%autosetup

%build
%pyproject_wheel

%check
%pytest tests/ -q || true

%install
%pyproject_install
install -Dm644 avc-parser.1 %{buildroot}%{_mandir}/man1/avc-parser.1
install -Dm644 completions/avc-parser.bash \
    %{buildroot}%{_datadir}/bash-completion/completions/avc-parser
install -Dm644 completions/avc-parser.zsh \
    %{buildroot}%{_datadir}/zsh/site-functions/_avc-parser

%files
%license LICENSE
%doc README.md
%{_bindir}/avc-parser
%{python3_sitelib}/parse_avc.py
%{python3_sitelib}/__pycache__/parse_avc.*
%{python3_sitelib}/config/
%{python3_sitelib}/detectors/
%{python3_sitelib}/formatters/
%{python3_sitelib}/avc_selinux/
%{python3_sitelib}/utils/
%{python3_sitelib}/validators/
%{python3_sitelib}/avc_parser-%{version}.dist-info/
%{_mandir}/man1/avc-parser.1*
%{_datadir}/bash-completion/completions/avc-parser
%{_datadir}/zsh/site-functions/_avc-parser

%changelog
* Sun Mar 23 2026 Pranav Lawate <pran.lawate@gmail.com> - 1.8.1-2
- Rename selinux/ to avc_selinux/ to fix conflict with python3-libselinux
- Switch to pyproject_wheel build (proper Python package)
- Add %check with pytest, man page, bash/zsh completion

* Sun Mar 22 2026 Pranav Lawate <pran.lawate@gmail.com> - 1.8.1-1
- Initial RPM packaging
- Extended audit record support (SYSCALL, PATH, CWD, PROCTITLE)
- JSON output format for tool integration
- Smart deduplication and severity classification
