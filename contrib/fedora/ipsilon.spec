Name:		ipsilon
Version:	0.1
Release:	1%{?dist}
Summary:	An Identity Provider Server

Group:		System Environment/Base
License:	GPLv3+
URL:		https://fedorahosted.org/ipsilon/
Source0:	ipsilon-%{version}.tar.gz

BuildRequires:	python2-devel
BuildRequires:	python-setuptools
BuildRequires:	lasso-python
Requires:	lasso-python
Requires(pre):  shadow-utils

%description
Ipsilon is a multi-protocol Identiy Provider service. Its function is to
bridge authentication providers and applications to achieve Single Sign On
and Federation.


%prep
%setup -q


%build
CFLAGS="$RPM_OPT_FLAGS" %{__python} setup.py build

%install
%{__python} setup.py install --skip-build --root $RPM_BUILD_ROOT
mkdir -p %{buildroot}%{_sbindir}
install -d -m 0700 %{buildroot}%{_sharedstatedir}/ipsilon
install -d -m 0700 %{buildroot}%{_sharedstatedir}/ipsilon/sessions
ln -s ../..%{python2_sitelib}/ipsilon/idpserver.py \
    %{buildroot}/%{_sbindir}/ipsilon.py
chmod +x %{buildroot}%{python2_sitelib}/ipsilon/idpserver.py
install -d -m 0700 %{buildroot}%{_sysconfdir}/ipsilon

%pre
getent group ipsilon >/dev/null || groupadd -r ipsilon
getent passwd ipsilon >/dev/null || \
    useradd -r -g ipsilon -d %{_sharedstatedir}/ipsilon -s /sbin/nologin \
    -c "Ipsilon Server" ipsilon
exit 0

%files
%doc COPYING
%{python2_sitelib}/*
%{_mandir}/man*/ipsilon*
%{_datadir}/ipsilon/*
%{_sbindir}/ipsilon.py
%dir %attr(0700,ipsilon,ipsilon) %{_sharedstatedir}/ipsilon
%dir %attr(0700,ipsilon,ipsilon) %{_sharedstatedir}/ipsilon/sessions
%dir %attr(0700,ipsilon,ipsilon) %{_sysconfdir}/ipsilon


%changelog
* Wed Jan 01 2014 Simo Sorce <simo@redhat.com> - 0.1
- Changelog
