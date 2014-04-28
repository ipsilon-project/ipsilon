Name:		ipsilon
Version:	0.2.1
Release:	1%{?dist}
Summary:	An Identity Provider Server

Group:		System Environment/Base
License:	GPLv3+
URL:		https://fedorahosted.org/ipsilon/
Source0:	ipsilon-%{version}.tar.gz

BuildRequires:	python2-devel
BuildRequires:	python-setuptools
BuildRequires:	lasso-python
Requires:       ipsilon-tools = %{version}-%{release}
Requires:	lasso-python
Requires:	mod_wsgi
Requires:	mod_auth_kerb
Requires:       python-cherrypy
Requires:       python-jinja2
Requires:       python-lxml
Requires:       python-pam
Requires(pre):  shadow-utils

%description
Ipsilon is a multi-protocol Identiy Provider service. Its function is to
bridge authentication providers and applications to achieve Single Sign On
and Federation.


%package tools
Summary:        Client tools for the Ipsilon IDP
Group:          System Environment/Base
License:        GPLv3+
Requires:       python-requests
Requires:       python-lxml
Requires:	lasso-python
Requires:	mod_auth_mellon

%description tools
Convenience client install tools for the Ipsilon identity Provider


%prep
%setup -q


%build
CFLAGS="$RPM_OPT_FLAGS" %{__python} setup.py build

%install
%{__python} setup.py install --skip-build --root $RPM_BUILD_ROOT
mkdir -p %{buildroot}%{_sbindir}
install -d -m 0700 %{buildroot}%{_sharedstatedir}/ipsilon
mv %{buildroot}/%{_bindir}/ipsilon %{buildroot}/%{_sbindir}
mv %{buildroot}/%{_bindir}/ipsilon-server-install %{buildroot}/%{_sbindir}
install -d -m 0700 %{buildroot}%{_sysconfdir}/ipsilon

%pre
getent group ipsilon >/dev/null || groupadd -r ipsilon
getent passwd ipsilon >/dev/null || \
    useradd -r -g ipsilon -d %{_sharedstatedir}/ipsilon -s /sbin/nologin \
    -c "Ipsilon Server" ipsilon
exit 0

%files
%doc COPYING
%{python2_sitelib}/ipsilon-*.egg-info
%{python2_sitelib}/ipsilon/admin/*
%{python2_sitelib}/ipsilon/login/*
%{python2_sitelib}/ipsilon/providers/*
%{python2_sitelib}/ipsilon/root.py*
%{python2_sitelib}/ipsilon/util/*
%{_mandir}/man*/ipsilon*
%{_datadir}/ipsilon/templates/*.html
%{_datadir}/ipsilon/templates/admin/*
%{_datadir}/ipsilon/templates/login/*
%{_datadir}/ipsilon/templates/saml2/*
%{_datadir}/ipsilon/templates/install/*.conf
%{_datadir}/ipsilon/ui/css/*
%{_datadir}/ipsilon/ui/img/*
%{_datadir}/ipsilon/ui/js/*
%{_sbindir}/ipsilon
%{_sbindir}/ipsilon-server-install
%dir %attr(0700,ipsilon,ipsilon) %{_sharedstatedir}/ipsilon
%dir %attr(0700,ipsilon,ipsilon) %{_sysconfdir}/ipsilon

%files tools
%doc COPYING
%{python2_sitelib}/ipsilon-*.egg-info
%{python2_sitelib}/ipsilon/__init__.py*
%{python2_sitelib}/ipsilon/tools/*
%{_datadir}/ipsilon/templates/install/saml2/sp.conf
%{_datadir}/ipsilon/ui/saml2sp/*
%{_bindir}/ipsilon-client-install
