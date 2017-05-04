#!/usr/bin/python
#
# Copyright (C) 2014 Ipsilon project Contributors, for license see COPYING

from __future__ import print_function

from helpers.common import IpsilonTestBase  # pylint: disable=relative-import
from helpers.http import HttpSessions  # pylint: disable=relative-import
import os
import pwd
import sys
import sqlite3
from string import Template
import time

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
         'cleanup_interval': 1,
         'session_timeout': 0.1,
         'server_debugging': 'True'}


sp_g = {'HTTPDCONFD': '${TESTDIR}/${NAME}/conf.d',
        'SAML2_TEMPLATE': '${TESTDIR}/templates/install/saml2/sp.conf',
        'CONFFILE': '${TESTDIR}/${NAME}/conf.d/ipsilon-%s.conf',
        'HTTPDIR': '${TESTDIR}/${NAME}/%s'}


sp_a = {'hostname': '${ADDRESS}',
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
        super(IpsilonTest, self).__init__('testcleanup', __file__)

    def setup_servers(self, env=None):
        print("Installing IDP server")
        name = 'idp1'
        addr = '127.0.0.10'
        port = '45080'
        idp = self.generate_profile(idp_g, idp_a, name, addr, port)
        conf = self.setup_idp_server(idp, name, addr, port, env)

        print("Starting IDP's httpd server")
        self.start_http_server(conf, env)

        print("Installing SP server")
        name = 'sp1'
        addr = '127.0.0.11'
        port = '45081'
        sp = self.generate_profile(sp_g, sp_a, name, addr, port)
        conf = self.setup_sp_server(sp, name, addr, port, env)
        fixup_sp_httpd(os.path.dirname(conf))

        print("Starting first SP's httpd server")
        self.start_http_server(conf, env)


if __name__ == '__main__':

    idpname = 'idp1'
    sp1name = 'sp1'
    user = pwd.getpwuid(os.getuid())[0]

    sess = HttpSessions()
    sess.add_server(idpname, 'https://127.0.0.10:45080', user, 'ipsilon')
    sess.add_server(sp1name, 'https://127.0.0.11:45081')

    print("testcleanup: Verify logged out state ...", end=' ')
    try:
        page = sess.fetch_page(idpname, 'https://127.0.0.10:45080/idp1/')
        page.expected_value('//div[@id="content"]/p/a/text()', 'Log In')
    except Exception as e:  # pylint: disable=broad-except
        print(" ERROR: %s" % repr(e), file=sys.stderr)
        sys.exit(1)
    print(" SUCCESS")

    print("testcleanup: Authenticate to IDP ...", end=' ')
    try:
        sess.auth_to_idp(idpname)
    except Exception as e:  # pylint: disable=broad-except
        print(" ERROR: %s" % repr(e), file=sys.stderr)
        sys.exit(1)
    print(" SUCCESS")

    print("testcleanup: Add SP Metadata to IDP ...", end=' ')
    try:
        sess.add_sp_metadata(idpname, sp1name)
    except Exception as e:  # pylint: disable=broad-except
        print(" ERROR: %s" % repr(e), file=sys.stderr)
        sys.exit(1)
    print(" SUCCESS")

    print("testcleanup: Access first SP Protected Area ...", end=' ')
    try:
        page = sess.fetch_page(idpname, 'https://127.0.0.11:45081/sp/')
        page.expected_value('text()', 'WORKS!')
    except ValueError as e:
        print(" ERROR: %s" % repr(e), file=sys.stderr)
        sys.exit(1)
    print(" SUCCESS")

    print("testcleanup: Verify logged in state ...", end=' ')
    try:
        page = sess.fetch_page(idpname, 'https://127.0.0.10:45080/idp1/')
        page.expected_value('//div[@id="content"]/p/a/text()', None)
    except Exception as e:  # pylint: disable=broad-except
        print(" ERROR: %s" % repr(e), file=sys.stderr)
        sys.exit(1)
    print(" SUCCESS")

    print("testcleanup: Checking that SAML2 sessions were created ...",
          end=' ')
    try:
        sess_db = os.path.join(os.environ['TESTDIR'],
                               'lib/idp1/saml2.sessions.db.sqlite')
        conn = sqlite3.connect(sess_db)
        cur = conn.cursor()
        cur.execute('SELECT * FROM saml2_sessions;')
        if len(cur.fetchall()) == 0:
            raise ValueError('SAML2 sessions not created')
        conn.close()
    except ValueError as e:
        print(" ERROR: %s" % repr(e), file=sys.stderr)
        sys.exit(1)
    print(" SUCCESS")

    # Sessions are valid for six seconds, and we clean up once per minute.
    # However, checking after a minute is kinda cutting it close, so we add ten
    # seconds to make sure the system has had time to clean up.
    print("Waiting a minute for cleanup to happen ...")
    time.sleep(70)

    print("testcleanup: Verify logged out state ...", end=' ')
    try:
        page = sess.fetch_page(idpname, 'https://127.0.0.10:45080/idp1/')
        page.expected_value('//div[@id="content"]/p/a/text()', 'Log In')
    except Exception as e:  # pylint: disable=broad-except
        print(" ERROR: %s" % repr(e), file=sys.stderr)
        sys.exit(1)
    print(" SUCCESS")

    print("testcleanup: Checking that SAML2 sessions were destroyed ...",
          end=' ')
    try:
        sess_db = os.path.join(os.environ['TESTDIR'],
                               'lib/idp1/saml2.sessions.db.sqlite')
        conn = sqlite3.connect(sess_db)
        cur = conn.cursor()
        cur.execute('SELECT * FROM saml2_sessions;')
        if len(cur.fetchall()) != 0:
            raise ValueError('SAML2 sessions left behind: %s' % cur.fetchall())
    except ValueError as e:
        print(" ERROR: %s" % repr(e), file=sys.stderr)
        sys.exit(1)
    print(" SUCCESS")
