#!/usr/bin/python
#
# Copyright (C) 2015-2017 Ipsilon project Contributors, for license see COPYING

from helpers.common import IpsilonTestBase  # pylint: disable=relative-import
from helpers.common import WRAP_HOSTNAME  # pylint: disable=relative-import
from helpers.common import TESTREALM  # pylint: disable=relative-import
from helpers.control import TC  # pylint: disable=relative-import
from helpers.http import HttpSessions  # pylint: disable=relative-import
from ipsilon.tools.saml2metadata import SAML2_NAMEID_MAP
import os
import pwd
import re
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
         'gssapi': 'yes',
         'gssapi_httpd_keytab': '${TESTDIR}/${HTTP_KTNAME}',
         'ipa': 'no',
         'server_debugging': 'True'}


sp_g = {'HTTPDCONFD': '${TESTDIR}/${NAME}/conf.d',
        'SAML2_TEMPLATE': '${TESTDIR}/templates/install/saml2/sp.conf',
        'CONFFILE': '${TESTDIR}/${NAME}/conf.d/ipsilon-%s.conf',
        'HTTPDIR': '${TESTDIR}/${NAME}/%s'}


sp_a = {'hostname': '${ADDRESS}',
        'saml_idp_metadata': 'https://%s:45080/idp1/saml2/metadata' %
        WRAP_HOSTNAME,
        'saml_auth': '/sp',
        'saml_nameid': '${NAMEID}',
        'httpd_user': '${TEST_USER}'}


def generate_sp_list():
    splist = []
    spport = 45081

    for nameid in SAML2_NAMEID_MAP:
        nameid = nameid
        spdata = {'nameid': nameid, 'addr': '127.0.0.11', 'port': str(spport)}
        splist.append(spdata)
        spport += 1

    return splist


def get_sp_by_nameid(splist, nameid):
    for server in splist:
        if server['nameid'] == nameid:
            return server

    return None


def convert_to_dict(envlist):
    values = {}
    for pair in envlist.split('\n'):
        if pair.find('=') > 0:
            (key, value) = pair.split('=', 1)
            values[key] = value
    return values


def fixup_sp_httpd(httpdir):
    location = """

AddOutputFilter INCLUDES .html

Alias /sp ${HTTPDIR}/sp

<Directory ${HTTPDIR}/sp>
    <IfModule mod_authz_core.c>
        Require all granted
    </IfModule>
    <IfModule !mod_authz_core.c>
        Order Allow,Deny
        Allow from All
    </IfModule>
    Options +Includes
</Directory>
"""
    index = """<!--#echo var="REMOTE_USER" -->"""

    t = Template(location)
    text = t.substitute({'HTTPDIR': httpdir})
    with open(httpdir + '/conf.d/ipsilon-saml.conf', 'a') as f:
        f.write(text)

    os.mkdir(httpdir + '/sp')
    with open(httpdir + '/sp/index.html', 'w') as f:
        f.write(index)


class IpsilonTest(IpsilonTestBase):

    def __init__(self):
        super(IpsilonTest, self).__init__('testnameid', __file__)

    def setup_servers(self, env=None):
        os.mkdir("%s/ccaches" % self.testdir)

        self.setup_step("Installing KDC server")
        kdcenv = self.setup_kdc(env)

        self.setup_step("Creating principals and keytabs")
        self.setup_keys(kdcenv)

        self.setup_step("Getting a TGT")
        self.kinit_keytab(kdcenv)

        self.setup_step("Installing IDP server")
        name = 'idp1'
        addr = WRAP_HOSTNAME
        port = '45080'
        idp = self.generate_profile(idp_g, idp_a, name, addr, port)
        conf = self.setup_idp_server(idp, name, addr, port, env)

        self.setup_step("Starting IDP's httpd server")
        env.update(kdcenv)
        self.start_http_server(conf, env)

        for spdata in generate_sp_list():
            nameid = spdata['nameid']
            addr = spdata['addr']
            port = spdata['port']
            self.setup_step("Installing SP server %s" % nameid)
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

    expected = {
        'x509':        True,   # not supported
        'transient':   False,
        'persistent':  False,
        'windows':     True,   # not supported
        'encrypted':   True,   # not supported
        'kerberos':    False,
        'email':       False,
        'unspecified': False,
        'entity':      True,   # not supported
    }

    expected_re = {
        'x509':        'Unauthorized',    # not supported
        'transient':   '_[0-9a-f]{32}',
        'persistent':  '_[0-9a-f]{128}',
        'windows':     'Unauthorized',    # not supported
        'encrypted':   'Unauthorized',    # not supported
        'kerberos':    '%s@%s' % (user, TESTREALM),
        'email':       '%s@.*' % user,
        'unspecified': user,
        'entity':      'Unauthorized',   # not supported
    }

    testdir = os.environ['TESTDIR']

    krb5conf = os.path.join(testdir, 'krb5.conf')
    kenv = {'PATH': '/sbin:/bin:/usr/sbin:/usr/bin',
            'KRB5_CONFIG': krb5conf,
            'KRB5CCNAME': 'FILE:' + os.path.join(testdir, 'ccaches/user')}

    for kkey in kenv:
        os.environ[kkey] = kenv[kkey]

    sp_list = generate_sp_list()
    for sp in sp_list:
        krb = False
        spname = sp['nameid']
        spurl = 'https://%s:%s' % (sp['addr'], sp['port'])
        sess = HttpSessions()
        sess.add_server(idpname, 'https://%s:45080' % WRAP_HOSTNAME, user,
                        'ipsilon')
        sess.add_server(spname, spurl)

        TC.info('Testing NameID format %s' % spname)

        if spname == 'kerberos':
            krb = True

        with TC.case('Authenticate to IdP'):
            sess.auth_to_idp(idpname, krb=krb)

        with TC.case('Add SP Metadata to IdP'):
            sess.add_sp_metadata(idpname, spname)

        with TC.case('Set supported Name ID formats'):
            sess.set_sp_default_nameids(idpname, spname, [spname])

        with TC.case('Access SP Protected Area',
                     should_fail=bool(expected[spname])):
            page = sess.fetch_page(idpname, '%s/sp/' % spurl)
            if not re.match(expected_re[spname], page.text):
                raise ValueError(
                    'page did not contain expression %s' %
                    expected_re[spname]
                )

        newsess = HttpSessions()
        newsess.add_server(idpname, 'https://%s:45080' % WRAP_HOSTNAME,
                           user, 'wrong')
        with TC.case('Try authentication failure', should_fail=True):
            newsess.auth_to_idp(idpname)

    # Ensure that transient names change with each authentication
    sp = get_sp_by_nameid(sp_list, 'transient')
    spname = sp['nameid']
    spurl = 'https://%s:%s' % (sp['addr'], sp['port'])

    TC.info('Testing NameID format %s' % spname)

    ids = []
    for i in xrange(4):
        sess = HttpSessions()
        sess.add_server(idpname, 'https://%s:45080' % WRAP_HOSTNAME,
                        user, 'ipsilon')
        sess.add_server(spname, spurl)
        with TC.case('Authenticate to IdP'):
            sess.auth_to_idp(idpname)

        with TC.case('Acess SP'):
            page = sess.fetch_page(idpname, '%s/sp/' % spurl)
            t1 = page.text

        with TC.case('Access SP again'):
            page = sess.fetch_page(idpname, '%s/sp/' % spurl)
            t2 = page.text

        with TC.case('Ensure ID is consistent between requests'):
            if t1 != t2:
                raise ValueError('Same ID between requests')

        ids.append(t1)

    with TC.case('Ensure uniqueness across sessions'):
        if len(ids) != len(set(ids)):
            raise ValueError('IDs are not unique between sessions')

    # Ensure that persistent names remain the same with each authentication
    sp = get_sp_by_nameid(sp_list, 'persistent')
    spname = sp['nameid']
    spurl = 'https://%s:%s' % (sp['addr'], sp['port'])

    TC.info('Testing NameID format %s' % spname)

    ids = []
    for i in xrange(4):
        sess = HttpSessions()
        sess.add_server(idpname, 'https://%s:45080' % WRAP_HOSTNAME,
                        user, 'ipsilon')
        sess.add_server(spname, spurl)
        with TC.case('Authenticate to IdP'):
            sess.auth_to_idp(idpname)

        with TC.case('Access SP'):
            page = sess.fetch_page(idpname, '%s/sp/' % spurl)
            t1 = page.text

        with TC.case('Access SP again'):
            page = sess.fetch_page(idpname, '%s/sp/' % spurl)
            t2 = page.text

        with TC.case('Ensure ID is consistent between requests'):
            if t1 != t2:
                raise ValueError('New ID between requests')

        ids.append(t1)

    with TC.case('Ensure same ID across sessions'):
        if len(set(ids)) != 1:
            raise ValueError('IDs are not the same between sessions')
