#!/usr/bin/python
#
# Copyright (C) 2014 Ipsilon project Contributors, for license see COPYING

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
         'users_dburi': 'postgresql://@127.0.0.10:45432/users',
         'database_url': 'postgresql://@127.0.0.10:45432/%(dbname)s',
         'session_type': 'sql',
         'session_dburi': 'postgresql://@127.0.0.10:45432/sessions',
         'admin_user': '${TEST_USER}',
         'system_user': '${TEST_USER}',
         'instance': '${NAME}',
         'openid': 'False',
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


class IpsilonTest(IpsilonTestBase):

    def __init__(self):
        super(IpsilonTest, self).__init__('pgdb', __file__)

    def setup_servers(self, env=None):

        print "Installing IDP's database server"
        datadir = os.path.join(self.testdir, 'pgdata')
        rundir = self.testdir
        log = os.path.join(self.testdir, 'log/pgdb.log')
        addr = '127.0.0.10'
        port = '45432'
        self.setup_pgdb(datadir, env)

        print "Starting IDP's database server"
        self.start_pgdb_server(datadir, rundir, log, addr, port, env)

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


if __name__ == '__main__':

    idpname = 'idp1'
    spname = 'sp1'
    user = pwd.getpwuid(os.getuid())[0]

    sess = HttpSessions()
    sess.add_server(idpname, 'http://127.0.0.10:45080', user, 'ipsilon')
    sess.add_server(spname, 'http://127.0.0.11:45081')

    print "pgdb: Authenticate to IDP ...",
    sys.stdout.flush()
    try:
        print 'Stress-testing the database connections...',
        sys.stdout.flush()
        for i in xrange(50):
            sess.auth_to_idp(idpname)
            sess.logout_from_idp(idpname)
        sess.auth_to_idp(idpname)
    except Exception, e:  # pylint: disable=broad-except
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "pgdb: Add SP Metadata to IDP ...",
    try:
        sess.add_sp_metadata(idpname, spname)
    except Exception, e:  # pylint: disable=broad-except
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "pgdb: Access SP Protected Area ...",
    try:
        page = sess.fetch_page(idpname, 'http://127.0.0.11:45081/sp/')
        page.expected_value('text()', 'WORKS!')
    except ValueError, e:
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "pgdb: Logout from SP ...",
    try:
        page = sess.fetch_page(idpname, '%s/%s?%s' % (
            'http://127.0.0.11:45081', 'saml2/logout',
            'ReturnTo=http://127.0.0.11:45081/open/logged_out.html'))
        page.expected_value('text()', 'Logged out')
    except ValueError, e:
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"
