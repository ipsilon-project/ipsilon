Name:		ipsilon
Version:	0.2.6
Release:	1%{?dist}
Summary:	An Identity Provider Server

Group:		System Environment/Base
License:	GPLv3+
URL:		https://fedorahosted.org/ipsilon/
Source0:	ipsilon-%{version}.tar.gz

BuildRequires:	python2-devel
BuildRequires:	python-setuptools
BuildRequires:	lasso-python
BuildRequires:  python-openid, python-openid-cla, python-openid-teams
Requires:       ipsilon-tools = %{version}-%{release}
Requires:       ipsilon-provider = %{version}-%{release}
Requires:	mod_wsgi
Requires:       mod_intercept_form_submit
Requires:       python-cherrypy
Requires:       python-jinja2
Requires:       python-lxml
Requires:       python-sqlalchemy
Requires(pre):  shadow-utils
Requires(post): %_sbindir/semanage, %_sbindir/restorecon
Requires(postun): %_sbindir/semanage

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


%package saml2
Summary:        SAML2 provider plugin
Group:          System Environment/Base
License:        GPLv3+
Provides:       ipsilon-provider = %{version}-%{release}
Requires:       lasso-python

%description saml2
Provides a SAML2 provider plugin for the Ipsilon identity Provider


%package openid
Summary:        Openid provider plugin
Group:          System Environment/Base
License:        GPLv3+
Provides:       ipsilon-provider = %{version}-%{release}
Requires:       python-openid
Requires:       python-openid-cla
Requires:       python-openid-teams

%description openid
Provides an OpenId provider plugin for the Ipsilon identity Provider


%package authfas
Summary:        Fedora Authentication System login plugin
Group:          System Environment/Base
License:        GPLv3+
Requires:       python-fedora

%description authfas
Provides a login plugin to authenticate agaist the Fedora Authentication System


%package authpam
Summary:        PAM based login plugin
Group:          System Environment/Base
License:        GPLv3+
Requires:       python-pam

%description authpam
Provides a login plugin to authenticate agaist the local PAM stack


%package authkrb
Summary:        mod_auth_kerb based login plugin
Group:          System Environment/Base
License:        GPLv3+
Requires:	mod_auth_kerb

%description authkrb
Provides a login plugin to allow authentication via the mod_auth_kerb Apache
module.


%package authldap
Summary:        mod_auth_kerb based login plugin
Group:          System Environment/Base
License:        GPLv3+
Requires:       python-ldap

%description authldap
Provides a login plugin to allow authentication and info retrieval via LDAP.


%prep
%setup -q


%build
CFLAGS="%{optflags}" %{__python} setup.py build

%install
%{__python} setup.py install --skip-build --root %{buildroot}
mkdir -p %{buildroot}%{_sbindir}
install -d -m 0700 %{buildroot}%{_sharedstatedir}/ipsilon
mv %{buildroot}/%{_bindir}/ipsilon %{buildroot}/%{_sbindir}
mv %{buildroot}/%{_bindir}/ipsilon-server-install %{buildroot}/%{_sbindir}
install -d -m 0700 %{buildroot}%{_sysconfdir}/ipsilon
mkdir -p %{buildroot}%{_defaultdocdir}
mv %{buildroot}%{_defaultdocdir}/%{name} %{buildroot}%{_defaultdocdir}/%{name}-%{version}
rm -fr %{buildroot}%{python2_sitelib}/tests

%pre
getent group ipsilon >/dev/null || groupadd -r ipsilon
getent passwd ipsilon >/dev/null || \
    useradd -r -g ipsilon -d %{_sharedstatedir}/ipsilon -s /sbin/nologin \
    -c "Ipsilon Server" ipsilon
exit 0

%post
semanage fcontext -a -t httpd_var_lib_t '%{_sharedstatedir}/ipsilon(/.*)?' || :
semanage fcontext -a -t var_lib_t '%{_sharedstatedir}/ipsilon(/.*)/*.conf' || :
restorecon -R %{_sharedstatedir}/ipsilon || :

%postun
# Clean up after package removal
if [ $1 -eq 0 ]; then
    semanage fcontext -d -t var_lib_t '%{_sharedstatedir}/ipsilon(/.*)/*.conf' || :
    semanage fcontext -d -t httpd_var_lib_t '%{_sharedstatedir}/ipsilon(/.*)?' || :
fi

%files
%{_defaultdocdir}/%{name}-%{version}
%{python2_sitelib}/ipsilon-*.egg-info
%{python2_sitelib}/ipsilon/admin/*
%{python2_sitelib}/ipsilon/login/__init__*
%{python2_sitelib}/ipsilon/login/common*
%{python2_sitelib}/ipsilon/login/authform*
%{python2_sitelib}/ipsilon/login/authtest*
%{python2_sitelib}/ipsilon/info/__init__*
%{python2_sitelib}/ipsilon/info/common*
%{python2_sitelib}/ipsilon/info/nss*
%{python2_sitelib}/ipsilon/providers/__init__*
%{python2_sitelib}/ipsilon/providers/common*
%{python2_sitelib}/ipsilon/root.py*
%{python2_sitelib}/ipsilon/util/*
%{_mandir}/man*/ipsilon*
%{_datadir}/ipsilon/templates/*.html
%{_datadir}/ipsilon/templates/admin/*
%{_datadir}/ipsilon/templates/login/index.html
%{_datadir}/ipsilon/templates/login/form.html
%{_datadir}/ipsilon/templates/install/*.conf
%{_datadir}/ipsilon/ui/css/*
%{_datadir}/ipsilon/ui/img/*
%{_datadir}/ipsilon/ui/js/*
%{_sbindir}/ipsilon
%{_sbindir}/ipsilon-server-install
%dir %attr(0700,ipsilon,ipsilon) %{_sharedstatedir}/ipsilon
%dir %attr(0700,ipsilon,ipsilon) %{_sysconfdir}/ipsilon

%files tools
%doc COPYING README
%{python2_sitelib}/ipsilon-*.egg-info
%{python2_sitelib}/ipsilon/__init__.py*
%{python2_sitelib}/ipsilon/tools/*
%{python2_sitelib}/ipsilon/helpers/*
%{_datadir}/ipsilon/templates/install/saml2/sp.conf
%{_datadir}/ipsilon/ui/saml2sp/*
%{_bindir}/ipsilon-client-install

%files saml2
%{python2_sitelib}/ipsilon/providers/saml2*
%{_datadir}/ipsilon/templates/saml2/*

%files openid
%{python2_sitelib}/ipsilon/providers/openid*
%{_datadir}/ipsilon/templates/openid/*

%files authfas
%{python2_sitelib}/ipsilon/login/authfas*

%files authpam
%{python2_sitelib}/ipsilon/login/authpam*

%files authkrb
%{python2_sitelib}/ipsilon/login/authkrb*
%{_datadir}/ipsilon/templates/login/krb.html

%files authldap
%{python2_sitelib}/ipsilon/login/authldap*
%{python2_sitelib}/ipsilon/info/infoldap*
