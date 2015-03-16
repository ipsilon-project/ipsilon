# Bundling request for bootstrap/patternfly: https://fedorahosted.org/fpc/ticket/483

Name:       ipsilon
Version:    0.5.0
Release:    1%{?builddate}%{?gittag}%{?dist}
Summary:    An Identity Provider Server

Group:      System Environment/Base
License:    GPLv3+
URL:        https://fedorahosted.org/ipsilon/
Source0:    https://fedorahosted.org/released/ipsilon/ipsilon-%{version}.tar.gz
BuildArch:  noarch


BuildRequires:  python2-devel
BuildRequires:  python-setuptools
BuildRequires:  lasso-python
BuildRequires:  python-openid, python-openid-cla, python-openid-teams
BuildRequires:  m2crypto

Requires:       python-requests
Requires:       %{name}-base = %{version}-%{release}
BuildArch:      noarch

%description
Ipsilon is a multi-protocol Identity Provider service. Its function is to
bridge authentication providers and applications to achieve Single Sign On
and Federation.


%package base
Summary:        Ipsilon base IDP server
Group:          System Environment/Base
License:        GPLv3+
Requires:       httpd
Requires:       mod_ssl
Requires:       %{name}-filesystem = %{version}-%{release}
Requires:       %{name}-provider = %{version}-%{release}
Requires:       mod_wsgi
Requires:       python-cherrypy
Requires:       python-jinja2
Requires:       python-lxml
Requires:       python-sqlalchemy
Requires:       open-sans-fonts
Requires(pre):  shadow-utils
Requires(post): %_sbindir/semanage, %_sbindir/restorecon
Requires(postun): %_sbindir/semanage


%description base
The Ipsilon IdP server without installer


%package filesystem
Summary:        Package providing files required by Ipsilon
Group:          System Environment/Base
License:        GPLv3+

%description filesystem
Package providing basic directory structure required
for all Ipsilon parts


%package client
Summary:        Tools for configuring Ipsilon clients
Group:          System Environment/Base
License:        GPLv3+
Requires:       %{name}-filesystem = %{version}-%{release}
Requires:       %{name}-saml2-base = %{version}-%{release}
Requires:       mod_auth_mellon
BuildArch:      noarch

%description client
Client install tools


%package tools-ipa
summary:        IPA helpers
Group:          System Environment/Base
License:        GPLv3+
Requires:       %{name}-authkrb = %{version}-%{release}
Requires:       %{name}-authform = %{version}-%{release}
%if 0%{?rhel}
Requires:       ipa-client
Requires:       ipa-admintools
%else
Requires:       freeipa-client
Requires:       freeipa-admintools
%endif
BuildArch:      noarch

%description tools-ipa
Convenience client install tools for IPA support in the Ipsilon identity Provider


%package saml2-base
Summary:        SAML2 base
Group:          System Environment/Base
License:        GPLv3+
Requires:       lasso-python
Requires:       python-lxml
BuildArch:      noarch

%description saml2-base
Provides core SAML2 utilities


%package saml2
Summary:        SAML2 provider plugin
Group:          System Environment/Base
License:        GPLv3+
Provides:       ipsilon-provider = %{version}-%{release}
Requires:       %{name} = %{version}-%{release}
Requires:       %{name}-saml2-base = %{version}-%{release}
BuildArch:      noarch

%description saml2
Provides a SAML2 provider plugin for the Ipsilon identity Provider


%package openid
Summary:        Openid provider plugin
Group:          System Environment/Base
License:        GPLv3+
Provides:       ipsilon-provider = %{version}-%{release}
Requires:       %{name} = %{version}-%{release}
Requires:       python-openid
Requires:       python-openid-cla
Requires:       python-openid-teams
BuildArch:      noarch

%description openid
Provides an OpenId provider plugin for the Ipsilon identity Provider


%package persona
Summary:        Persona provider plugin
Group:          System Environment/Base
License:        GPLv3+
Provides:       ipsilon-provider = %{version}-%{release}
Requires:       %{name} = %{version}-%{release}
Requires:       m2crypto
BuildArch:      noarch

%description persona
Provides a Persona provider plugin for the Ipsilon identity Provider


%package authfas
Summary:        Fedora Authentication System login plugin
Group:          System Environment/Base
License:        GPLv3+
Requires:       %{name} = %{version}-%{release}
Requires:       python-fedora
BuildArch:      noarch

%description authfas
Provides a login plugin to authenticate against the Fedora Authentication System


%package authform
Summary:        mod_intercept_form_submit login plugin
Group:          System Environment/Base
License:        GPLv3+
Requires:       %{name} = %{version}-%{release}
Requires:       mod_intercept_form_submit
BuildArch:      noarch

%description authform
Provides a login plugin to authenticate with mod_intercept_form_submit


%package authpam
Summary:        PAM based login plugin
Group:          System Environment/Base
License:        GPLv3+
Requires:       %{name} = %{version}-%{release}
Requires:       python-pam
BuildArch:      noarch

%description authpam
Provides a login plugin to authenticate against the local PAM stack


%package authkrb
Summary:        mod_auth_kerb based login plugin
Group:          System Environment/Base
License:        GPLv3+
Requires:       %{name} = %{version}-%{release}
Requires:       mod_auth_kerb
BuildArch:      noarch

%description authkrb
Provides a login plugin to allow authentication via the mod_auth_kerb Apache
module.


%package authldap
Summary:        mod_auth_kerb based login plugin
Group:          System Environment/Base
License:        GPLv3+
Requires:       %{name} = %{version}-%{release}
Requires:       python-ldap
BuildArch:      noarch

%description authldap
Provides a login plugin to allow authentication and info retrieval via LDAP.

%package infosssd
Summary:        SSSD & mod_lookup_identity-based identity plugin
Group:          System Environment/Base
License:        GPLv3+
Requires:       %{name} = %{version}-%{release}
Requires:       mod_lookup_identity
Requires:       libsss_simpleifp
Requires:       sssd >= 1.12.4
BuildArch:      noarch

%description infosssd
Provides an info plugin to allow retrieval via mod_lookup_identity and
SSSD.

%prep
%setup -q


%build
CFLAGS="%{optflags}" %{__python} setup.py build


%install
%{__python} setup.py install --skip-build --root %{buildroot}
mkdir -p %{buildroot}%{_sbindir}
mkdir -p %{buildroot}%{_defaultdocdir}
# These 0700 permissions are because ipsilon will store private keys here
install -d -m 0700 %{buildroot}%{_sharedstatedir}/ipsilon
install -d -m 0700 %{buildroot}%{_sysconfdir}/ipsilon
mv %{buildroot}/%{_bindir}/ipsilon %{buildroot}/%{_sbindir}
mv %{buildroot}/%{_bindir}/ipsilon-server-install %{buildroot}/%{_sbindir}
mv %{buildroot}%{_defaultdocdir}/%{name} %{buildroot}%{_defaultdocdir}/%{name}-%{version}
rm -fr %{buildroot}%{python2_sitelib}/tests
ln -s %{_datadir}/fonts %{buildroot}%{_datadir}/ipsilon/ui/fonts

#%check
# The test suite is not being run because:
#  1. The last step of %%install removes the entire test suite
#  2. It increases build time a lot
#  3. It adds more build dependencies (namely postgresql server and client libraries)

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


%files filesystem
%doc COPYING README
%dir %{_datadir}/ipsilon
%dir %{_datadir}/ipsilon/templates
%dir %{_datadir}/ipsilon/templates/install
%dir %{python2_sitelib}/ipsilon
%{python2_sitelib}/ipsilon/__init__.py*
%{python2_sitelib}/ipsilon-*.egg-info
%dir %{python2_sitelib}/ipsilon/tools
%{python2_sitelib}/ipsilon/tools/__init__.py*
%{python2_sitelib}/ipsilon/tools/files.py*

%files
%{_sbindir}/ipsilon-server-install
%{_datadir}/ipsilon/templates/install/*.conf
%{_datadir}/ipsilon/ui/saml2sp
%dir %{python2_sitelib}/ipsilon/helpers
%{python2_sitelib}/ipsilon/helpers/common.py*
%{python2_sitelib}/ipsilon/helpers/__init__.py*

%files base
%{_defaultdocdir}/%{name}-%{version}
%{python2_sitelib}/ipsilon/admin
%{python2_sitelib}/ipsilon/rest
%dir %{python2_sitelib}/ipsilon/login
%{python2_sitelib}/ipsilon/login/__init__*
%{python2_sitelib}/ipsilon/login/common*
%{python2_sitelib}/ipsilon/login/authtest*
%dir %{python2_sitelib}/ipsilon/info
%{python2_sitelib}/ipsilon/info/__init__*
%{python2_sitelib}/ipsilon/info/common*
%{python2_sitelib}/ipsilon/info/infonss*
%dir %{python2_sitelib}/ipsilon/providers
%{python2_sitelib}/ipsilon/providers/__init__*
%{python2_sitelib}/ipsilon/providers/common*
%{python2_sitelib}/ipsilon/root.py*
%{python2_sitelib}/ipsilon/util
%{_mandir}/man*/ipsilon*
%{_datadir}/ipsilon/templates/*.html
%{_datadir}/ipsilon/templates/admin
%dir %{_datadir}/ipsilon/templates/login
%{_datadir}/ipsilon/templates/login/index.html
%{_datadir}/ipsilon/templates/login/form.html
%dir %{_datadir}/ipsilon/ui
%{_datadir}/ipsilon/ui/css
%{_datadir}/ipsilon/ui/img
%{_datadir}/ipsilon/ui/js
%{_datadir}/ipsilon/ui/fonts
%{_sbindir}/ipsilon
%dir %attr(0700,ipsilon,ipsilon) %{_sharedstatedir}/ipsilon
%dir %attr(0700,ipsilon,ipsilon) %{_sysconfdir}/ipsilon

%files client
%{_bindir}/ipsilon-client-install
%{_datadir}/ipsilon/templates/install/saml2

%files tools-ipa
%{python2_sitelib}/ipsilon/helpers/ipa.py*

%files saml2-base
%{python2_sitelib}/ipsilon/tools/saml2metadata.py*
%{python2_sitelib}/ipsilon/tools/certs.py*

%files saml2
%{python2_sitelib}/ipsilon/providers/saml2*
%{_datadir}/ipsilon/templates/saml2

%files openid
%{python2_sitelib}/ipsilon/providers/openid*
%{_datadir}/ipsilon/templates/openid

%files persona
%{python2_sitelib}/ipsilon/providers/persona*
%{_datadir}/ipsilon/templates/persona

%files authfas
%{python2_sitelib}/ipsilon/login/authfas*

%files authform
%{python2_sitelib}/ipsilon/login/authform*

%files authpam
%{python2_sitelib}/ipsilon/login/authpam*

%files authkrb
%{python2_sitelib}/ipsilon/login/authkrb*
%{_datadir}/ipsilon/templates/login/krb.html

%files authldap
%{python2_sitelib}/ipsilon/login/authldap*
%{python2_sitelib}/ipsilon/info/infoldap*

%files infosssd
%{python2_sitelib}/ipsilon/info/infosssd.*

%changelog
* Mon Mar 30 2015 Patrick Uiterwijk <puiterwijk@redhat.com> - 0.5.0-1
- Released 0.5.0

* Fri Feb 27 2015 Patrick Uiterwijk <puiterwijk@redhat.com> - 0.4.0-1
- Released 0.4.0

* Tue Feb 24 2015 Patrick Uiterwijk <puiterwijk@redhat.com> - 0.3.0-7
- Split the installer into -tools
- Split authform into -authform

* Thu Feb 12 2015 Rob Crittenden <rcritten@redhat.com> - 0.3.0-6
- Add mod_identity_lookup info plugin package

* Wed Jan 28 2015 Patrick Uiterwijk <puiterwijk@redhat.com> - 0.3.0-5
- Split IPA tools

* Mon Jan 12 2015 Patrick Uiterwijk <puiterwijk@redhat.com> - 0.3.0-4
- Add symlink to fonts directory

* Tue Dec 16 2014 Patrick Uiterwijk <puiterwijk@redhat.com> - 0.3.0-3
- Fix typo
- Add comments on why the test suite is not in check
- The subpackages require the base package
- Add link to FPC ticket for bundling exception request

* Tue Dec 16 2014 Patrick Uiterwijk <puiterwijk@redhat.com> - 0.3.0-2
- Fix shebang removal

* Tue Dec 16 2014 Patrick Uiterwijk <puiterwijk@redhat.com> - 0.3.0-1
- Initial packaging
