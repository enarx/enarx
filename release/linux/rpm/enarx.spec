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
%ifarch x86_64
mkdir -p %{buildroot}/usr/lib/enarx
cp -r %{source_sig_x86_64} %{buildroot}/usr/lib/enarx/enarx.sig
%endif

%files
%license LICENSE
%attr(0755, root, root) %{_bindir}/enarx
%ifarch x86_64
/usr/lib/enarx/enarx.sig
%attr(0444, root, root) /usr/lib/enarx/enarx.sig
%endif

%changelog
* Thu Sep 01 2022 Patrick Uiterwijk <patrick@puiterwijk.org>
- Initial Packaging
