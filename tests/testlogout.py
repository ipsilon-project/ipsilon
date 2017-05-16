#!/usr/bin/python
#
# Copyright (C) 2015-2017 Ipsilon project Contributors, for license see COPYING

from helpers.common import IpsilonTestBase  # pylint: disable=relative-import
from helpers.control import TC  # pylint: disable=relative-import
from helpers.http import HttpSessions  # pylint: disable=relative-import
import os
import pwd
from string import Template


idp_g = {'TEMPLATES': '${TESTDIR}/templates/install',
         'CONFDIR': '${TESTDIR}/etc',
         'DATADIR': '${TESTDIR}/lib',
         'CACHEDIR': '${TESTDIR}/cache',
         'HTTPDCONFD': '${TESTDIR}/${NAME}/conf.d',
         'STATICDIR': '${ROOTDIR}',
         'BINDIR': '${ROOTDIR}/ipsilon',
         'WSGI_SOCKET_PREFIX': '${TESTDIR}/${NAME}/logs/wsgi'}


idp_a = {'hostname': '${ADDRESS}:${PORT}',
         'admin_user': '${TEST_USER}',
         'system_user': '${TEST_USER}',
         'instance': '${NAME}',
         'testauth': 'yes',
         'pam': 'no',
         'gssapi': 'no',
         'ipa': 'no',
         'server_debugging': 'True'}


sp_g = {'HTTPDCONFD': '${TESTDIR}/${NAME}/conf.d',
        'SAML2_TEMPLATE': '${TESTDIR}/templates/install/saml2/sp.conf',
        'CONFFILE': '${TESTDIR}/${NAME}/conf.d/ipsilon-%s.conf',
        'HTTPDIR': '${TESTDIR}/${NAME}/%s'}


sp_a = {'hostname': '${ADDRESS}',
        'saml_idp_metadata': 'https://127.0.0.10:45080/idp1/saml2/metadata',
        'saml_auth': '/sp',
        'httpd_user': '${TEST_USER}'}


sp_b = {'hostname': '${ADDRESS}',
        'saml_idp_metadata': 'https://127.0.0.10:45080/idp1/saml2/metadata',
        'no_saml_soap_logout': 'True',
        'saml_auth': '/sp',
        'httpd_user': '${TEST_USER}'}


# Global list of SP's
splist = [
    {
        'nameid': 'sp1',
        'addr': '127.0.0.11',
        'port': '45081',
    },
    {
        'nameid': 'sp2',
        'addr': '127.0.0.11',
        'port': '45082',
    },
    {
        'nameid': 'sp3',
        'addr': '127.0.0.11',
        'port': '45083',
    },
    {
        'nameid': 'sp4',
        'addr': '127.0.0.11',
        'port': '45084',
    },
    {
        'nameid': 'sp5',
        'addr': '127.0.0.11',
        'port': '45085',
    },
]


def fixup_sp_httpd(httpdir):
    location = """

Alias /sp ${HTTPDIR}/sp

<Directory ${HTTPDIR}/sp>
    <IfModule mod_authz_core.c>
        Require all granted
    </IfModule>
    <IfModule !mod_authz_core.c>
        Order Allow,Deny
        Allow from All
    </IfModule>
</Directory>

Alias /open ${HTTPDIR}/open

<Directory ${HTTPDIR}/open>
</Directory>
"""
    index = """WORKS!"""
    logged_out = """Logged out"""

    t = Template(location)
    text = t.substitute({'HTTPDIR': httpdir})
    with open(httpdir + '/conf.d/ipsilon-saml.conf', 'a') as f:
        f.write(text)

    os.mkdir(httpdir + '/sp')
    with open(httpdir + '/sp/index.html', 'w') as f:
        f.write(index)
    os.mkdir(httpdir + '/open')
    with open(httpdir + '/open/logged_out.html', 'w') as f:
        f.write(logged_out)


def ensure_logout(session, idp_name, sp_url):
    """
    Fetch the secure page without following redirects. If we get
    a 303 then we should be redirected to the IDP for authentication
    which means we aren't logged in.

    Returns nothing or raises exception on error
    """
    try:
        logout_page = session.fetch_page(idp_name, sp_url,
                                         follow_redirect=False)
        if logout_page.result.status_code != 303:
            raise ValueError('Still logged into url')
    except ValueError:
        raise

    return True


class IpsilonTest(IpsilonTestBase):

    def __init__(self):
        super(IpsilonTest, self).__init__('testlogout', __file__)

    def setup_servers(self, env=None):
        self.setup_step("Installing IDP server")
        name = 'idp1'
        addr = '127.0.0.10'
        port = '45080'
        idp = self.generate_profile(idp_g, idp_a, name, addr, port)
        conf = self.setup_idp_server(idp, name, addr, port, env)

        self.setup_step("Starting IDP's httpd server")
        self.start_http_server(conf, env)

        for spdata in splist:
            nameid = spdata['nameid']
            addr = spdata['addr']
            port = spdata['port']
            self.setup_step("Installing SP server %s" % nameid)

            # Configure sp3 and sp4 for only HTTP Redirect to test
            # that a mix of SOAP and HTTP Redirect will play nice
            # together.
            if nameid in ['sp3', 'sp4']:
                sp_prof = self.generate_profile(
                    sp_g, sp_b, nameid, addr, str(port), nameid
                )
            else:
                sp_prof = self.generate_profile(
                    sp_g, sp_a, nameid, addr, str(port), nameid
                )
            conf = self.setup_sp_server(sp_prof, nameid, addr, str(port), env)
            fixup_sp_httpd(os.path.dirname(conf))

            self.setup_step("Starting SP's httpd server")
            self.start_http_server(conf, env)


if __name__ == '__main__':

    idpname = 'idp1'
    user = pwd.getpwuid(os.getuid())[0]

    sess = HttpSessions()
    sess.add_server(idpname, 'https://127.0.0.10:45080', user, 'ipsilon')
    for sp in splist:
        spname = sp['nameid']
        spurl = 'https://%s:%s' % (sp['addr'], sp['port'])
        sess.add_server(spname, spurl)

    with TC.case('Authenticate to IdP'):
        sess.auth_to_idp(idpname)

    for sp in splist:
        spname = sp['nameid']
        with TC.case('Add SP Metadata for %s to IdP' % spname):
            sess.add_sp_metadata(idpname, spname)

    with TC.case('Logout without logging into SP'):
        page = sess.fetch_page(idpname, '%s/%s?%s' % (
            'https://127.0.0.11:45081', 'saml2/logout',
            'ReturnTo=https://127.0.0.11:45081/open/logged_out.html'))
        page.expected_value('text()', 'Logged out')

    with TC.case('Access SP Protected Area'):
        page = sess.fetch_page(idpname, 'https://127.0.0.11:45081/sp/')
        page.expected_value('text()', 'WORKS!')

    with TC.case('Logout from SP'):
        page = sess.fetch_page(idpname, '%s/%s?%s' % (
            'https://127.0.0.11:45081', 'saml2/logout',
            'ReturnTo=https://127.0.0.11:45081/open/logged_out.html'))
        page.expected_value('text()', 'Logged out')

    with TC.case('Try logout again'):
        page = sess.fetch_page(idpname, '%s/%s?%s' % (
            'https://127.0.0.11:45081', 'saml2/logout',
            'ReturnTo=https://127.0.0.11:45081/open/logged_out.html'))
        page.expected_value('text()', 'Logged out')

    with TC.case('Ensure logout'):
        ensure_logout(sess, idpname, 'https://127.0.0.11:45081/sp/')

    # Test logout from each of the SP's in the list to ensure that the
    # order of logout doesn't matter.
    for sporder in splist:
        with TC.case('Access SP PRotected Area of all SPs'):
            for sp in splist:
                spname = sp['nameid']
                spurl = 'https://%s:%s/sp/' % (sp['addr'], sp['port'])
                page = sess.fetch_page(idpname, spurl)
                page.expected_value('text()', 'WORKS!')

        with TC.case('Initiate logout from %s' % sporder['nameid']):
            logouturl = 'https://%s:%s' % (sp['addr'], sp['port'])
            page = sess.fetch_page(idpname, '%s/%s?%s' % (
                logouturl, 'saml2/logout',
                'ReturnTo=https://127.0.0.11:45081/open/logged_out.html'))
            page.expected_value('text()', 'Logged out')

        with TC.case('Ensure logout of each SP'):
            for sp in splist:
                spname = sp['nameid']
                spurl = 'https://%s:%s/sp/' % (sp['addr'], sp['port'])
                ensure_logout(sess, idpname, spurl)

    # Test IdP-initiated logout
    with TC.case('Access SP Protected area of SP1'):
        page = sess.fetch_page(idpname, 'https://127.0.0.11:45081/sp/')
        page.expected_value('text()', 'WORKS!')

    with TC.case('Access SP Protected Area of SP2'):
        page = sess.fetch_page(idpname, 'https://127.0.0.11:45082/sp/')
        page.expected_value('text()', 'WORKS!')

    with TC.case('Access the IdP'):
        page = sess.fetch_page(idpname,
                               'https://127.0.0.10:45080/%s' % idpname)
        page.expected_value('//div[@id="welcome"]/p/text()',
                            'Welcome %s!' % user)

    with TC.case('IdP-initiated logout'):
        page = sess.fetch_page(idpname,
                               'https://127.0.0.10:45080/%s/logout' % idpname)
        page.expected_value('//div[@id="content"]/p/a/text()', 'Log In')

    with TC.case('Ensure logout of SP1'):
        ensure_logout(sess, idpname, 'https://127.0.0.11:45081/sp/')

    with TC.case('Ensure logout of SP2'):
        ensure_logout(sess, idpname, 'https://127.0.0.11:45082/sp/')

    with TC.case('Access the IdP'):
        page = sess.fetch_page(idpname,
                               'https://127.0.0.10:45080/%s/login' % idpname)
        page.expected_value('//div[@id="welcome"]/p/text()',
                            'Welcome %s!' % user)

    with TC.case('IdP-initiated logout with no SP sessions'):
        page = sess.fetch_page(idpname,
                               'https://127.0.0.10:45080/%s/logout' % idpname)
        page.expected_value('//div[@id="logout"]/p//text()',
                            'Successfully logged out.')
