Name:           enarx
Version:        %{version}
Release:        1
Summary:        Confidential Computing with WebAssembly

License:        ASL 2.0
URL:            https://enarx.dev/

%description
This package provides the enarx command-line tool for running applications inside Trusted Execution Environments (TEEs) using technologies such as Intel SGX and AMD SEV-SNP.

%prep
cp %{source_license} %{_builddir}

%build
# Pre-built

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p %{buildroot}%{_bindir}
cp -r %{source_binary} %{buildroot}%{_bindir}/enarx

%files
%license LICENSE
%attr(0755, root, root) %{_bindir}/enarx

%changelog
* Thu Sep 01 2022 Patrick Uiterwijk <patrick@puiterwijk.org>
- Initial Packaging
