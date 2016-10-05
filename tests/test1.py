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
         'saml_idp_url': 'https://127.0.0.10:45080/idp1',
         'admin_user': '${TEST_USER}',
         'admin_password': '${TESTDIR}/pw.txt',
         'saml_sp_name': 'sp2-test.example.com',
         'saml_auth': '/sp',
         'httpd_user': '${TEST_USER}'}

keyless_metadata = """<?xml version='1.0' encoding='UTF-8'?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#" cacheDuration="P7D"
    entityID="http://keyless-sp">
  <md:SPSSODescriptor
        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:AssertionConsumerService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="http://keyless-sp/postResponse" index="0"/>
    <md:NameIDFormat>
urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
  </md:SPSSODescriptor>
</md:EntityDescriptor>
"""


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
        super(IpsilonTest, self).__init__('test1', __file__)

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
        sp = self.generate_profile(sp_g, sp_a, name, addr, port)
        conf = self.setup_sp_server(sp, name, addr, port, env)
        fixup_sp_httpd(os.path.dirname(conf))

        print "Starting first SP's httpd server"
        self.start_http_server(conf, env)

        print "Installing second SP server"
        name = 'sp2-test.example.com'
        addr = '127.0.0.11'
        port = '45082'
        sp = self.generate_profile(sp2_g, sp2_a, name, addr, port)
        with open(os.path.dirname(sp) + '/pw.txt', 'a') as f:
            f.write('ipsilon')
        conf = self.setup_sp_server(sp, name, addr, port, env)
        os.remove(os.path.dirname(sp) + '/pw.txt')
        fixup_sp_httpd(os.path.dirname(conf))

        print "Starting second SP's httpd server"
        self.start_http_server(conf, env)


if __name__ == '__main__':

    idpname = 'idp1'
    sp1name = 'sp1'
    sp2name = 'sp2-test.example.com'
    user = pwd.getpwuid(os.getuid())[0]

    sess = HttpSessions()
    sess.add_server(idpname, 'https://127.0.0.10:45080', user, 'ipsilon')
    sess.add_server(sp1name, 'https://127.0.0.11:45081')
    sess.add_server(sp2name, 'https://127.0.0.11:45082')

    print "test1: Authenticate to IDP ...",
    try:
        sess.auth_to_idp(idpname)
    except Exception, e:  # pylint: disable=broad-except
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "test1: Add first SP Metadata to IDP ...",
    try:
        sess.add_sp_metadata(idpname, sp1name)
    except Exception, e:  # pylint: disable=broad-except
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "test1: Access first SP Protected Area ...",
    try:
        page = sess.fetch_page(idpname, 'https://127.0.0.11:45081/sp/')
        page.expected_value('text()', 'WORKS!')
    except ValueError, e:
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "test1: Access second SP Protected Area ...",
    try:
        page = sess.fetch_page(idpname, 'https://127.0.0.11:45082/sp/')
        page.expected_value('text()', 'WORKS!')
    except ValueError, e:
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "test1: Update second SP ...",
    try:
        # This is a test to see whether we can update SAML SPs where the name
        # is an FQDN (includes hyphens and dots). See bug #196
        sess.set_attributes_and_mapping(idpname, [],
                                        ['namefull', 'givenname', 'surname'],
                                        spname=sp2name)
    except Exception, e:  # pylint: disable=broad-except
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    else:
        print " SUCCESS"

    print "test1: Try authentication failure ...",
    newsess = HttpSessions()
    newsess.add_server(idpname, 'https://127.0.0.10:45080', user, 'wrong')
    try:
        newsess.auth_to_idp(idpname)
        print >> sys.stderr, " ERROR: Authentication should have failed"
        sys.exit(1)
    except Exception, e:  # pylint: disable=broad-except
        print " SUCCESS"

    print "test1: Add keyless SP Metadata to IDP ...",
    try:
        sess.add_metadata(idpname, 'keyless', keyless_metadata)
        page = sess.fetch_page(idpname, 'https://127.0.0.10:45080/idp1/admin/'
                                        'providers/saml2/admin')
        page.expected_value('//div[@id="row_provider_http://keyless-sp"]/'
                            '@title',
                            'WARNING: SP does not have signing keys!')
    except Exception, e:  # pylint: disable=broad-except
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"
