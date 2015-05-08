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

sp3_g = {'HTTPDCONFD': '${TESTDIR}/${NAME}/conf.d',
         'SAML2_TEMPLATE': '${TESTDIR}/templates/install/saml2/sp.conf',
         'SAML2_CONFFILE': '${TESTDIR}/${NAME}/conf.d/ipsilon-saml.conf',
         'SAML2_HTTPDIR': '${TESTDIR}/${NAME}/saml2'}


sp3_a = {'hostname': '${ADDRESS}:${PORT}',
         'saml_idp_metadata': 'http://127.0.0.10:45080/idp1/saml2/metadata',
         'saml_secure_setup': 'False',
         'saml_auth': '/sp',
         'httpd_user': '${TEST_USER}'}


def fixup_sp_httpd(httpdir, alias):
    location = """

Alias /${ALIAS} ${HTTPDIR}/sp

<Directory ${HTTPDIR}/${ALIAS}>
    Require all granted
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
        fixup_sp_httpd(os.path.dirname(conf), name)

        print "Starting SP's httpd server"
        self.start_http_server(conf, env)

        print "Installing second SP server"
        name = 'sp2'
        addr = '127.0.0.10'
        port = '45082'
        sp2 = self.generate_profile(sp2_g, sp2_a, name, addr, port)
        conf = self.setup_sp_server(sp2, name, addr, port, env)
        fixup_sp_httpd(os.path.dirname(conf), name)

        print "Starting SP's httpd server"
        self.start_http_server(conf, env)

        print "Installing third SP server"
        name = 'sp3.invalid'
        addr = '127.0.0.10'
        port = '45083'
        sp3 = self.generate_profile(sp3_g, sp3_a, name, addr, port)
        conf = self.setup_sp_server(sp3, name, addr, port, env)
        fixup_sp_httpd(os.path.dirname(conf), name)

        print "Starting SP's httpd server"
        self.start_http_server(conf, env)


if __name__ == '__main__':

    idpname = 'idp1'
    spname = 'sp1'
    sp2name = 'sp2'
    sp3name = 'sp3.invalid'
    user = pwd.getpwuid(os.getuid())[0]

    sess = HttpSessions()
    sess.add_server(idpname, 'http://127.0.0.10:45080', user, 'ipsilon')
    sess.add_server(spname, 'http://127.0.0.11:45081')
    sess.add_server(sp2name, 'http://127.0.0.10:45082')
    sess.add_server(sp3name, 'http://127.0.0.10:45083')

    print "testrest: Authenticate to IDP ...",
    try:
        sess.auth_to_idp(idpname)
    except Exception, e:  # pylint: disable=broad-except
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "testrest: List initial Service Providers via REST ...",
    try:
        result = sess.get_rest_sp(idpname)
        if len(result['result']) != 0:
            raise ValueError(
                'Expected no SP and got %d' % len(result['result'])
            )
    except ValueError, e:
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "testrest: Add SP Metadata to IDP via admin ...",
    try:
        sess.add_sp_metadata(idpname, spname)
    except Exception, e:  # pylint: disable=broad-except
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "testrest: List Service Providers via REST ...",
    try:
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
    except ValueError, e:
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "testrest: Add Service Provider via REST ...",
    try:
        sess.add_sp_metadata(idpname, sp2name, rest=True)
    except ValueError, e:
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "testrest: List Service Providers via REST ...",
    try:
        result = sess.get_rest_sp(idpname)
        if len(result['result']) != 2:
            raise ValueError(
                'Expected 2 SPs and got %d' % len(result['result'])
            )
    except ValueError, e:
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "testrest: List Specific Service Providers via REST ...",
    try:
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
    except ValueError, e:
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    # Now for some negative testing

    print "testrest: Add illegally named Service Provider via REST ...",
    try:
        sess.add_sp_metadata(idpname, sp3name, rest=True)
    except ValueError, e:
        print " SUCCESS"
    else:
        print >> sys.stderr, "ERROR: " \
            "Adding SP with invalid name should have failed and it didn't"
        sys.exit(1)

    print "testrest: Fetch non-existent REST endpoint ...",
    try:
        result = sess.fetch_rest_page(
            idpname,
            '/%s/rest/providers/saml2/notfound' % idpname
        )
    except ValueError, e:
        if '(501)' not in e.message:
            print >> sys.stderr, " ERROR: %s" % repr(e)
            sys.exit(1)
        else:
            print " SUCCESS"
    else:
        print >> sys.stderr, "ERROR: should have returned a 404"
        sys.exit(1)

    print "testrest: Fetch non-existent SP via REST ...",
    try:
        result = sess.get_rest_sp(idpname, 'foo')
    except ValueError, e:
        if '(404)' not in e.message:
            print >> sys.stderr, " ERROR: %s" % repr(e)
            sys.exit(1)
        else:
            print " SUCCESS"
    else:
        print >> sys.stderr, "ERROR: should have returned a 404"
        sys.exit(1)

    print "testrest: Re-add Service Provider via REST ...",
    try:
        sess.add_sp_metadata(idpname, sp2name, rest=True)
    except ValueError, e:
        print " SUCCESS"
    else:
        print >> sys.stderr, "ERROR: " \
            "Adding duplicate SP should have failed and it didn't"
        sys.exit(1)
