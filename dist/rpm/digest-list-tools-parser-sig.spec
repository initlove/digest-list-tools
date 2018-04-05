name:           digest-list-tools-parser-sig
Version:        0.2
Release:        1%{?dist}
Summary:        Digest list parser signature

Source0:        parser_data
Source1:        parser_data.sig
Source2:        parser_metadata
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
License:        GPL-2.0
Url:            https://github.com/euleros/digest-list-tools
Requires:       digest-list-tools
BuildRequires:  digest-list-tools
BuildArch:      noarch

%description
This package includes the signature of the digest list parser.

%prep

%build

%install
mkdir -p ${RPM_BUILD_ROOT}%{_sysconfdir}/ima/digest_lists
cp %{SOURCE0} ${RPM_BUILD_ROOT}%{_sysconfdir}/ima/digest_lists/
cp %{SOURCE1} ${RPM_BUILD_ROOT}%{_sysconfdir}/ima/digest_lists/
cp %{SOURCE2} ${RPM_BUILD_ROOT}%{_sysconfdir}/ima/digest_lists/

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%{_sysconfdir}/ima/digest_lists/parser_data
%{_sysconfdir}/ima/digest_lists/parser_data.sig
%{_sysconfdir}/ima/digest_lists/parser_metadata

%changelog

* Thu Apr 05 2018 Roberto Sassu <roberto.sassu@huawei.com> - 0.2
- PGP signatures
- Multiple digest algorithms
- User space digest list parser
- DEB package format

* Wed Nov 15 2017 Roberto Sassu <roberto.sassu@huawei.com> - 0.1
- Initial version
