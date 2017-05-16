#!/usr/bin/python
#
# Copyright (C) 2014-2017 Ipsilon project Contributors, for license see COPYING

from helpers.common import IpsilonTestBase  # pylint: disable=relative-import
from helpers.control import TC  # pylint: disable=relative-import
from helpers.http import HttpSessions  # pylint: disable=relative-import
import os
import pwd
import inspect
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
         'openid': 'yes',
         'openid_extensions': 'Attribute Exchange,Simple Registration,Teams',
         'pam': 'no',
         'gssapi': 'no',
         'ipa': 'no',
         'server_debugging': 'True'}


def fixup_sp_httpd(httpdir, testdir):
    client_wsgi = """

WSGIScriptAlias / ${TESTDIR}/blobs/openid_app.py

<Directory ${TESTDIR}/blobs>
    <IfModule mod_authz_core.c>
        Require all granted
    </IfModule>
    <IfModule !mod_authz_core.c>
        Order Allow,Deny
        Allow from All
    </IfModule>
</Directory>
"""
    t = Template(client_wsgi)
    text = t.substitute({'TESTDIR': testdir})
    with open(httpdir + '/conf.d/ipsilon-openid-client.conf', 'a') as f:
        f.write(text)


class IpsilonTest(IpsilonTestBase):

    def __init__(self):
        super(IpsilonTest, self).__init__('openid', __file__)

    def setup_servers(self, env=None):
        self.setup_step("Installing IDP server")
        name = 'idp1'
        addr = '127.0.0.10'
        port = '45080'
        idp = self.generate_profile(idp_g, idp_a, name, addr, port)
        conf = self.setup_idp_server(idp, name, addr, port, env)

        self.setup_step("Starting IDP's httpd server")
        self.start_http_server(conf, env)

        self.setup_step("Installing first SP server")
        name = 'sp1'
        addr = '127.0.0.11'
        port = '45081'
        conf = self.setup_http(name, addr, port)
        testdir = os.path.dirname(os.path.abspath(inspect.getfile(
            inspect.currentframe())))
        fixup_sp_httpd(os.path.dirname(conf), testdir)

        self.setup_step("Starting SP's httpd server")
        self.start_http_server(conf, env)


if __name__ == '__main__':

    idpname = 'idp1'
    sp1name = 'sp1'
    user = pwd.getpwuid(os.getuid())[0]

    sess = HttpSessions()
    sess.add_server(idpname, 'https://127.0.0.10:45080', user, 'ipsilon')
    sess.add_server(sp1name, 'https://127.0.0.11:45081')

    with TC.case('Authenticate to IdP'):
        sess.auth_to_idp(idpname)

    with TC.case('Run OpenID Protocol'):
        page = sess.fetch_page(idpname,
                               'https://127.0.0.11:45081/?extensions=NO',
                               require_consent=True)
        page.expected_value('text()', 'SUCCESS, WITHOUT EXTENSIONS')

    with TC.case('Run OpenID Protocol without consent'):
        page = sess.fetch_page(idpname,
                               'https://127.0.0.11:45081/?extensions=NO',
                               require_consent=False)
        page.expected_value('text()', 'SUCCESS, WITHOUT EXTENSIONS')

    with TC.case('Revoking SP consent'):
        page = sess.revoke_all_consent(idpname)

    with TC.case('Run OpenID Protocol without consent'):
        page = sess.fetch_page(idpname,
                               'https://127.0.0.11:45081/?extensions=NO',
                               require_consent=True)
        page.expected_value('text()', 'SUCCESS, WITHOUT EXTENSIONS')

    with TC.case('Run OpenID PRotocol with extensions'):
        # We expect consent again because we added more attributes
        page = sess.fetch_page(idpname,
                               'https://127.0.0.11:45081/?extensions=YES',
                               require_consent=True)
        page.expected_value('text()', 'SUCCESS, WITH EXTENSIONS')

    with TC.case('Set IdP authz stack to deny'):
        sess.disable_plugin(idpname, 'authz', 'allow')
        sess.enable_plugin(idpname, 'authz', 'deny')

    sess2 = HttpSessions()
    sess2.add_server(idpname, 'https://127.0.0.10:45080', user, 'ipsilon')
    sess2.add_server(sp1name, 'https://127.0.0.11:45081')

    with TC.case('Run OpenID Protocol with IdP deny, with pre-auth'):
        sess2.auth_to_idp(idpname)
        page = sess2.fetch_page(idpname,
                                'https://127.0.0.11:45081/?extensions=NO')
        page.expected_value('text()', 'ERROR: Cancelled')

    sess3 = HttpSessions()
    sess3.add_server(idpname, 'https://127.0.0.10:45080', user, 'ipsilon')
    sess3.add_server(sp1name, 'https://127.0.0.11:45081')

    with TC.case('Run OpenID Protocol with IdP deny, without pre-auth'):
        page = sess3.fetch_page(idpname,
                                'https://127.0.0.11:45081/?extensions=NO')
        page.expected_value('text()', 'ERROR: Cancelled')
