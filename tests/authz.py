#!/usr/bin/python
#
# Copyright (C) 2016 Ipsilon project Contributors, for license see COPYING

from helpers.common import IpsilonTestBase  # pylint: disable=relative-import
from helpers.http import HttpSessions  # pylint: disable=relative-import
import os
import pwd
import sys
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
         'testauth_groups': 'sp1',
         'authz_allow': 'yes',
         'authz_deny': 'no',
         'authz_spgroup': 'no',
         'pam': 'no',
         'gssapi': 'no',
         'ipa': 'no',
         'server_debugging': 'True'}


sp1_g = {'HTTPDCONFD': '${TESTDIR}/${NAME}/conf.d',
         'SAML2_TEMPLATE': '${TESTDIR}/templates/install/saml2/sp.conf',
         'CONFFILE': '${TESTDIR}/${NAME}/conf.d/ipsilon-%s.conf',
         'HTTPDIR': '${TESTDIR}/${NAME}/%s'}


sp1_a = {'hostname': '${ADDRESS}',
         'saml_idp_metadata': 'https://127.0.0.10:45080/idp1/saml2/metadata',
         'saml_auth': '/sp',
         'httpd_user': '${TEST_USER}'}


sp2_g = {'HTTPDCONFD': '${TESTDIR}/${NAME}/conf.d',
         'SAML2_TEMPLATE': '${TESTDIR}/templates/install/saml2/sp.conf',
         'CONFFILE': '${TESTDIR}/${NAME}/conf.d/ipsilon-%s.conf',
         'HTTPDIR': '${TESTDIR}/${NAME}/%s'}


sp2_a = {'hostname': '${ADDRESS}',
         'saml_idp_metadata': 'https://127.0.0.10:45080/idp1/saml2/metadata',
         'saml_auth': '/sp',
         'httpd_user': '${TEST_USER}'}


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
"""
    index = """WORKS!"""

    t = Template(location)
    text = t.substitute({'HTTPDIR': httpdir})
    with open(httpdir + '/conf.d/ipsilon-saml.conf', 'a') as f:
        f.write(text)

    os.mkdir(httpdir + '/sp')
    with open(httpdir + '/sp/index.html', 'w') as f:
        f.write(index)


class IpsilonTest(IpsilonTestBase):

    def __init__(self):
        super(IpsilonTest, self).__init__('authz', __file__)

    def setup_servers(self, env=None):
        print "Installing IDP server"
        name = 'idp1'
        addr = '127.0.0.10'
        port = '45080'
        idp = self.generate_profile(idp_g, idp_a, name, addr, port)
        conf = self.setup_idp_server(idp, name, addr, port, env)

        print "Starting IDP's httpd server"
        self.start_http_server(conf, env)

        print "Installing first SP server"
        name = 'sp1'
        addr = '127.0.0.11'
        port = '45081'
        sp = self.generate_profile(sp1_g, sp1_a, name, addr, port)
        conf = self.setup_sp_server(sp, name, addr, port, env)
        fixup_sp_httpd(os.path.dirname(conf))

        print "Starting first SP's httpd server"
        self.start_http_server(conf, env)

        print "Installing second SP server"
        name = 'sp2'
        addr = '127.0.0.12'
        port = '45082'
        sp = self.generate_profile(sp2_g, sp2_a, name, addr, port)
        conf = self.setup_sp_server(sp, name, addr, port, env)
        fixup_sp_httpd(os.path.dirname(conf))

        print "Starting second SP's httpd server"
        self.start_http_server(conf, env)


if __name__ == '__main__':

    idpname = 'idp1'
    sp1name = 'sp1'
    sp2name = 'sp2'
    user = pwd.getpwuid(os.getuid())[0]

    sess = HttpSessions()
    sess.add_server(idpname, 'https://127.0.0.10:45080', user, 'ipsilon')
    sess.add_server(sp1name, 'https://127.0.0.11:45081')
    sess.add_server(sp2name, 'https://127.0.0.12:45082')

    print "authz: Authenticate to IDP ...",
    try:
        sess.auth_to_idp(idpname)
    except Exception, e:  # pylint: disable=broad-except
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "authz: Add SP1 Metadata to IDP ...",
    try:
        sess.add_sp_metadata(idpname, sp1name)
    except Exception, e:  # pylint: disable=broad-except
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "authz: Add SP2 Metadata to IDP ...",
    try:
        sess.add_sp_metadata(idpname, sp2name)
    except Exception, e:  # pylint: disable=broad-except
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "authz: Access SP1 when authz stack set to allow ...",
    try:
        page = sess.fetch_page(idpname, 'https://127.0.0.11:45081/sp/')
        page.expected_value('text()', 'WORKS!')
    except ValueError, e:
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "authz: Set IDP authz stack to deny ...",
    try:
        sess.disable_plugin(idpname, 'authz', 'allow')
        sess.enable_plugin(idpname, 'authz', 'deny')
    except Exception, e:  # pylint: disable=broad-except
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    sess2 = HttpSessions()
    sess2.add_server(idpname, 'https://127.0.0.10:45080', user, 'ipsilon')
    sess2.add_server(sp1name, 'https://127.0.0.11:45081')

    print "authz: Fail access SP1 when authz stack set to deny, with " \
        "pre-auth ...",
    try:
        sess2.auth_to_idp(idpname)
        page = sess2.fetch_page(idpname, 'https://127.0.0.11:45081/sp/')
        page.expected_status(401)
    except Exception, e:  # pylint: disable=broad-except
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    sess3 = HttpSessions()
    sess3.add_server(idpname, 'https://127.0.0.10:45080', user, 'ipsilon')
    sess3.add_server(sp1name, 'https://127.0.0.11:45081')

    print "authz: Fail access SP1 when authz stack set to deny, without " \
        "pre-auth ...",
    try:
        page = sess3.fetch_page(idpname, 'https://127.0.0.11:45081/sp/')
        page.expected_status(401)
    except Exception, e:  # pylint: disable=broad-except
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "authz: Set IDP authz stack to spgroup ...",
    try:
        sess.disable_plugin(idpname, 'authz', 'deny')
        sess.enable_plugin(idpname, 'authz', 'spgroup')
    except Exception, e:  # pylint: disable=broad-except
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    sess4 = HttpSessions()
    sess4.add_server(idpname, 'https://127.0.0.10:45080', user, 'ipsilon')
    sess4.add_server(sp1name, 'https://127.0.0.11:45081')
    sess4.add_server(sp2name, 'https://127.0.0.12:45082')

    print "authz: Access SP1 when authz stack set to spgroup ...",
    try:
        sess4.auth_to_idp(idpname)
        page = sess4.fetch_page(idpname, 'https://127.0.0.11:45081/sp/')
        page.expected_value('text()', 'WORKS!')
    except ValueError, e:
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "authz: Fail to access SP2 when authz stack set to spgroup ...",
    try:
        page = sess4.fetch_page(idpname, 'https://127.0.0.12:45082/sp/')
        page.expected_status(401)
    except Exception, e:  # pylint: disable=broad-except
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"
