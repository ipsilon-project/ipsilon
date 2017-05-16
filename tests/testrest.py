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


sp2_g = {'HTTPDCONFD': '${TESTDIR}/${NAME}/conf.d',
         'SAML2_TEMPLATE': '${TESTDIR}/templates/install/saml2/sp.conf',
         'CONFFILE': '${TESTDIR}/${NAME}/conf.d/ipsilon-%s.conf',
         'HTTPDIR': '${TESTDIR}/${NAME}/%s'}


sp2_a = {'hostname': '${ADDRESS}',
         'saml_idp_metadata': 'https://127.0.0.10:45080/idp1/saml2/metadata',
         'saml_auth': '/sp',
         'httpd_user': '${TEST_USER}'}

sp3_g = {'HTTPDCONFD': '${TESTDIR}/${NAME}/conf.d',
         'SAML2_TEMPLATE': '${TESTDIR}/templates/install/saml2/sp.conf',
         'CONFFILE': '${TESTDIR}/${NAME}/conf.d/ipsilon-%s.conf',
         'HTTPDIR': '${TESTDIR}/${NAME}/%s'}


sp3_a = {'hostname': '${ADDRESS}',
         'saml_idp_metadata': 'https://127.0.0.10:45080/idp1/saml2/metadata',
         'saml_auth': '/sp',
         'httpd_user': '${TEST_USER}'}


def fixup_sp_httpd(httpdir, alias):
    location = """

Alias /${ALIAS} ${HTTPDIR}/sp

<Directory ${HTTPDIR}/${ALIAS}>
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
    text = t.substitute({'HTTPDIR': httpdir, 'ALIAS': alias})
    with open(httpdir + '/conf.d/ipsilon-saml.conf', 'a') as f:
        f.write(text)

    os.mkdir(httpdir + '/sp')
    with open(httpdir + '/sp/index.html', 'w') as f:
        f.write(index)


class IpsilonTest(IpsilonTestBase):

    def __init__(self):
        super(IpsilonTest, self).__init__('testrest', __file__)

    def setup_servers(self, env=None):
        self.setup_step("Installing IDP server")
        name = 'idp1'
        addr = '127.0.0.10'
        port = '45080'
        idp = self.generate_profile(idp_g, idp_a, name, addr, port)
        conf = self.setup_idp_server(idp, name, addr, port, env)

        self.setup_step("Starting IDP's httpd server")
        self.start_http_server(conf, env)

        self.setup_step("Installing SP server")
        name = 'sp1'
        addr = '127.0.0.11'
        port = '45081'
        sp = self.generate_profile(sp_g, sp_a, name, addr, port)
        conf = self.setup_sp_server(sp, name, addr, port, env)
        fixup_sp_httpd(os.path.dirname(conf), name)

        self.setup_step("Starting SP's httpd server")
        self.start_http_server(conf, env)

        self.setup_step("Installing second SP server")
        name = 'sp2-test.example.com'
        addr = '127.0.0.10'
        port = '45082'
        sp2 = self.generate_profile(sp2_g, sp2_a, name, addr, port)
        conf = self.setup_sp_server(sp2, name, addr, port, env)
        fixup_sp_httpd(os.path.dirname(conf), name)

        self.setup_step("Starting SP's httpd server")
        self.start_http_server(conf, env)

        self.setup_step("Installing third SP server")
        name = 'sp3_invalid'
        addr = '127.0.0.10'
        port = '45083'
        sp3 = self.generate_profile(sp3_g, sp3_a, name, addr, port)
        conf = self.setup_sp_server(sp3, name, addr, port, env)
        fixup_sp_httpd(os.path.dirname(conf), name)

        self.setup_step("Starting SP's httpd server")
        self.start_http_server(conf, env)


if __name__ == '__main__':

    idpname = 'idp1'
    spname = 'sp1'
    sp2name = 'sp2-test.example.com'
    sp3name = 'sp3_invalid'
    user = pwd.getpwuid(os.getuid())[0]

    sess = HttpSessions()
    sess.add_server(idpname, 'https://127.0.0.10:45080', user, 'ipsilon')
    sess.add_server(spname, 'https://127.0.0.11:45081')
    sess.add_server(sp2name, 'https://127.0.0.10:45082')
    sess.add_server(sp3name, 'https://127.0.0.10:45083')

    with TC.case('Authenticate to IdP'):
        sess.auth_to_idp(idpname)

    with TC.case('List initial Service Providers via REST'):
        result = sess.get_rest_sp(idpname)
        if len(result['result']) != 0:
            raise ValueError(
                'Expected no SP and got %d' % len(result['result'])
            )

    with TC.case('Add SP Metadata to IdP via admin'):
        sess.add_sp_metadata(idpname, spname)

    with TC.case('List Service Providers via REST'):
        result = sess.get_rest_sp(idpname)
        if len(result['result']) != 1:
            raise ValueError(
                'Expected 1 SP and got %d' % len(result['result'])
            )
        if result['result'][0].get('provider') != spname:
            raise ValueError(
                'Expected %s and got %s' %
                (spname, result['result'][0].get('provider'))
            )

    with TC.case('Add Service Provider via REST'):
        sess.add_sp_metadata(idpname, sp2name, rest=True)

    with TC.case('List Service Providers via REST'):
        result = sess.get_rest_sp(idpname)
        if len(result['result']) != 2:
            raise ValueError(
                'Expected 2 SPs and got %d' % len(result['result'])
            )

    with TC.case('List specific Service Providers via REST'):
        result = sess.get_rest_sp(idpname, spname)
        if len(result['result']) != 1:
            raise ValueError(
                'Expected 1 SPs and got %d' % len(result['result'])
            )
        if result['result'][0].get('provider') != spname:
            raise ValueError(
                'Expected %s and got %s' %
                (spname, result['result'][0].get('provider'))
            )

        # Now sp2, which has a name with extended characters
        result = sess.get_rest_sp(idpname, sp2name)
        if len(result['result']) != 1:
            raise ValueError(
                'Expected 1 SPs and got %d' % len(result['result'])
            )
        if result['result'][0].get('provider') != sp2name:
            raise ValueError(
                'Expected %s and got %s' %
                (spname, result['result'][0].get('provider'))
            )

    # Now for some negative testing

    with TC.case('Add illegally named Service Provider via REST',
                 should_fail='[400]'):
        sess.add_sp_metadata(idpname, sp3name, rest=True)

    with TC.case('Fetch non-existent REST endpoint',
                 should_fail='(501)'):
        result = sess.fetch_rest_page(
            idpname,
            '/%s/rest/providers/saml2/notfound' % idpname
        )

    with TC.case('Fetch non-existent SP via REST',
                 should_fail='(404)'):
        result = sess.get_rest_sp(idpname, 'foo')

    with TC.case('Re-add Service Provider via REST',
                 should_fail='[400]'):
        sess.add_sp_metadata(idpname, sp2name, rest=True)
