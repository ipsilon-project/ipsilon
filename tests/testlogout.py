#!/usr/bin/python
#
# Copyright (C) 2015 Ipsilon project Contributors, for license see COPYING

from helpers.common import IpsilonTestBase  # pylint: disable=relative-import
from helpers.http import HttpSessions  # pylint: disable=relative-import
import os
import pwd
import sys
from string import Template


idp_g = {'TEMPLATES': '${TESTDIR}/templates/install',
         'CONFDIR': '${TESTDIR}/etc',
         'DATADIR': '${TESTDIR}/lib',
         'HTTPDCONFD': '${TESTDIR}/${NAME}/conf.d',
         'STATICDIR': '${ROOTDIR}',
         'BINDIR': '${ROOTDIR}/ipsilon',
         'WSGI_SOCKET_PREFIX': '${TESTDIR}/${NAME}/logs/wsgi'}


idp_a = {'hostname': '${ADDRESS}:${PORT}',
         'admin_user': '${TEST_USER}',
         'system_user': '${TEST_USER}',
         'instance': '${NAME}',
         'secure': 'no',
         'testauth': 'yes',
         'pam': 'no',
         'gssapi': 'no',
         'ipa': 'no',
         'server_debugging': 'True'}


sp_g = {'HTTPDCONFD': '${TESTDIR}/${NAME}/conf.d',
        'SAML2_TEMPLATE': '${TESTDIR}/templates/install/saml2/sp.conf',
        'SAML2_CONFFILE': '${TESTDIR}/${NAME}/conf.d/ipsilon-saml.conf',
        'SAML2_HTTPDIR': '${TESTDIR}/${NAME}/saml2'}


sp_a = {'hostname': '${ADDRESS}:${PORT}',
        'saml_idp_metadata': 'http://127.0.0.10:45080/idp1/saml2/metadata',
        'saml_secure_setup': 'False',
        'saml_auth': '/sp',
        'httpd_user': '${TEST_USER}'}


sp2_g = {'HTTPDCONFD': '${TESTDIR}/${NAME}/conf.d',
         'SAML2_TEMPLATE': '${TESTDIR}/templates/install/saml2/sp.conf',
         'SAML2_CONFFILE': '${TESTDIR}/${NAME}/conf.d/ipsilon-saml.conf',
         'SAML2_HTTPDIR': '${TESTDIR}/${NAME}/saml2'}


sp2_a = {'hostname': '${ADDRESS}:${PORT}',
         'saml_idp_metadata': 'http://127.0.0.10:45080/idp1/saml2/metadata',
         'saml_secure_setup': 'False',
         'saml_auth': '/sp',
         'httpd_user': '${TEST_USER}'}


def fixup_sp_httpd(httpdir):
    location = """

Alias /sp ${HTTPDIR}/sp

<Directory ${HTTPDIR}/sp>
    Require all granted
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


def ensure_logout(session, idp_name, spurl):
    """
    Fetch the secure page without following redirects. If we get
    a 303 then we should be redirected to the IDP for authentication
    which means we aren't logged in.

    Returns nothing or raises exception on error
    """
    try:
        logout_page = session.fetch_page(idp_name, spurl,
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
        print "Installing IDP server"
        name = 'idp1'
        addr = '127.0.0.10'
        port = '45080'
        idp = self.generate_profile(idp_g, idp_a, name, addr, port)
        conf = self.setup_idp_server(idp, name, addr, port, env)

        print "Starting IDP's httpd server"
        self.start_http_server(conf, env)

        print "Installing SP server"
        name = 'sp1'
        addr = '127.0.0.11'
        port = '45081'
        sp = self.generate_profile(sp_g, sp_a, name, addr, port)
        conf = self.setup_sp_server(sp, name, addr, port, env)
        fixup_sp_httpd(os.path.dirname(conf))

        print "Starting SP's httpd server"
        self.start_http_server(conf, env)

        print "Installing second SP server"
        name = 'sp2'
        addr = '127.0.0.10'
        port = '45082'
        sp2 = self.generate_profile(sp2_g, sp2_a, name, addr, port)
        conf = self.setup_sp_server(sp2, name, addr, port, env)
        fixup_sp_httpd(os.path.dirname(conf))

        print "Starting SP's httpd server"
        self.start_http_server(conf, env)


if __name__ == '__main__':

    idpname = 'idp1'
    spname = 'sp1'
    sp2name = 'sp2'
    user = pwd.getpwuid(os.getuid())[0]

    sess = HttpSessions()
    sess.add_server(idpname, 'http://127.0.0.10:45080', user, 'ipsilon')
    sess.add_server(spname, 'http://127.0.0.11:45081')
    sess.add_server(sp2name, 'http://127.0.0.10:45082')

    print "testlogout: Authenticate to IDP ...",
    try:
        sess.auth_to_idp(idpname)
    except Exception, e:  # pylint: disable=broad-except
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "testlogout: Add SP Metadata to IDP ...",
    try:
        sess.add_sp_metadata(idpname, spname)
    except Exception, e:  # pylint: disable=broad-except
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "testlogout: Add second SP Metadata to IDP ...",
    try:
        sess.add_sp_metadata(idpname, sp2name)
    except Exception, e:  # pylint: disable=broad-except
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "testlogout: Logout without logging into SP ...",
    try:
        page = sess.fetch_page(idpname, '%s/%s?%s' % (
            'http://127.0.0.11:45081', 'saml2/logout',
            'ReturnTo=http://127.0.0.11:45081/open/logged_out.html'))
        page.expected_value('text()', 'Logged out')
    except ValueError, e:
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "testlogout: Access SP Protected Area ...",
    try:
        page = sess.fetch_page(idpname, 'http://127.0.0.11:45081/sp/')
        page.expected_value('text()', 'WORKS!')
    except ValueError, e:
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "testlogout: Logout from SP ...",
    try:
        page = sess.fetch_page(idpname, '%s/%s?%s' % (
            'http://127.0.0.11:45081', 'saml2/logout',
            'ReturnTo=http://127.0.0.11:45081/open/logged_out.html'))
        page.expected_value('text()', 'Logged out')
    except ValueError, e:
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "testlogout: Try logout again ...",
    try:
        page = sess.fetch_page(idpname, '%s/%s?%s' % (
            'http://127.0.0.11:45081', 'saml2/logout',
            'ReturnTo=http://127.0.0.11:45081/open/logged_out.html'))
        page.expected_value('text()', 'Logged out')
    except ValueError, e:
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "testlogout: Ensure logout ...",
    try:
        ensure_logout(sess, idpname, 'http://127.0.0.11:45081/sp/')
    except ValueError, e:
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "testlogout: Access SP Protected Area of SP1...",
    try:
        page = sess.fetch_page(idpname, 'http://127.0.0.11:45081/sp/')
        page.expected_value('text()', 'WORKS!')
    except ValueError, e:
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "testlogout: Access SP Protected Area of SP2...",
    try:
        page = sess.fetch_page(idpname, 'http://127.0.0.10:45082/sp/')
        page.expected_value('text()', 'WORKS!')
    except ValueError, e:
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "testlogout: Logout from both ...",
    try:
        page = sess.fetch_page(idpname, '%s/%s?%s' % (
            'http://127.0.0.11:45081', 'saml2/logout',
            'ReturnTo=http://127.0.0.11:45081/open/logged_out.html'))
        page.expected_value('text()', 'Logged out')
    except ValueError, e:
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "testlogout: Ensure logout of SP1 ...",
    try:
        ensure_logout(sess, idpname, 'http://127.0.0.11:45081/sp/')
    except ValueError, e:
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "testlogout: Ensure logout of SP2 ...",
    try:
        ensure_logout(sess, idpname, 'http://127.0.0.10:45082/sp/')
    except ValueError, e:
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    # Test IdP-initiated logout
    print "testlogout: Access SP Protected Area of SP1...",
    try:
        page = sess.fetch_page(idpname, 'http://127.0.0.11:45081/sp/')
        page.expected_value('text()', 'WORKS!')
    except ValueError, e:
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "testlogout: Access SP Protected Area of SP2...",
    try:
        page = sess.fetch_page(idpname, 'http://127.0.0.10:45082/sp/')
        page.expected_value('text()', 'WORKS!')
    except ValueError, e:
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "testlogout: Access the IdP...",
    try:
        page = sess.fetch_page(idpname, 'http://127.0.0.10:45080/%s' % idpname)
        page.expected_value('//div[@id="welcome"]/p/text()',
                            'Welcome %s!' % user)
    except ValueError, e:
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "testlogout: IdP-initiated logout ...",
    try:
        page = sess.fetch_page(idpname,
                               'http://127.0.0.10:45080/%s/logout' % idpname)
        page.expected_value('//div[@id="content"]/p/a/text()', 'Log In')
    except ValueError, e:
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "testlogout: Ensure logout of SP1 ...",
    try:
        ensure_logout(sess, idpname, 'http://127.0.0.11:45081/sp/')
    except ValueError, e:
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "testlogout: Ensure logout of SP2 ...",
    try:
        ensure_logout(sess, idpname, 'http://127.0.0.10:45082/sp/')
    except ValueError, e:
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "testlogout: Access the IdP...",
    try:
        page = sess.fetch_page(idpname,
                               'http://127.0.0.10:45080/%s/login' % idpname)
        page.expected_value('//div[@id="welcome"]/p/text()',
                            'Welcome %s!' % user)
    except ValueError, e:
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "testlogout: IdP-initiated logout with no SP sessions...",
    try:
        page = sess.fetch_page(idpname,
                               'http://127.0.0.10:45080/%s/logout' % idpname)
        page.expected_value('//div[@id="logout"]/p//text()',
                            'Successfully logged out.')
    except ValueError, e:
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"
