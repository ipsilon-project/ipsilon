#!/usr/bin/python
#
# Copyright (C) 2014 Ipsilon project Contributors, for license see COPYING

from helpers.common import IpsilonTestBase  # pylint: disable=relative-import
from helpers.http import HttpSessions  # pylint: disable=relative-import
import ConfigParser
import os
import pwd
import sys
from string import Template
import uuid


idpname = 'idp1'
idpaddr = '127.0.0.10'
idpport = '45080'
spname = 'sp1'
spaddr = '127.0.0.11'
spport = '45081'


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

idp_file_conf = """
[login_config]
global enabled = testauth
[provider_config]
global enabled = openid,saml2
openid endpoint url = ${IDPURI}/openid/
openid identity_url_template = ${IDPURI}/openid/id/%(username)s
saml2 idp key file = ${TESTDIR}/lib/${NAME}/saml2/idp.key
saml2 idp storage path = ${TESTDIR}/lib/${NAME}/saml2
saml2 idp metadata file = metadata.xml
saml2 idp certificate file = ${TESTDIR}/lib/${NAME}/saml2/idp.pem
saml2 idp nameid salt = ${IDPSALT}
[saml2_data]
811d0231-9362-46c9-a105-a01a64818904 id = http://${SPADDR}:${SPPORT}/saml2
811d0231-9362-46c9-a105-a01a64818904 type = SP
811d0231-9362-46c9-a105-a01a64818904 name = ${SPNAME}
811d0231-9362-46c9-a105-a01a64818904 metadata = ${SPMETA}
"""

sp_g = {'HTTPDCONFD': '${TESTDIR}/${NAME}/conf.d',
        'SAML2_TEMPLATE': '${TESTDIR}/templates/install/saml2/sp.conf',
        'SAML2_CONFFILE': '${TESTDIR}/${NAME}/conf.d/ipsilon-saml.conf',
        'SAML2_HTTPDIR': '${TESTDIR}/${NAME}/saml2'}


sp_a = {'hostname': '${ADDRESS}:${PORT}',
        'saml_idp_metadata': '${TESTDIR}/lib/idp1/saml2/metadata.xml',
        'saml_secure_setup': 'False',
        'saml_auth': '/sp',
        'httpd_user': '${TEST_USER}'}


def fixup_sp_httpd(httpdir):
    location = """

Alias /sp ${HTTPDIR}/sp

<Directory ${HTTPDIR}/sp>
    Require all granted
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


def fixup_idp_conf(testdir):

    with open(os.path.join(testdir, spname, 'saml2',
                           '%s:%s' % (spaddr, spport), 'metadata.xml')) as f:
        spmeta = f.read()
    spmeta = spmeta.replace("\n", "")

    idpuri = "http://%s:%s/%s" % (idpaddr, idpport, idpname)

    idpsalt = uuid.uuid4().hex
    t = Template(idp_file_conf)
    text = t.substitute({'NAME': idpname, 'IDPURI': idpuri,
                         'SPNAME': spname, 'SPADDR': spaddr, 'SPPORT': spport,
                         'SPMETA': spmeta, 'TESTDIR': testdir,
                         'IDPSALT': idpsalt})

    adminconf = os.path.join(testdir, 'etc/admin.conf')
    with open(adminconf, 'w+') as f:
        f.write(text)

    ipsilonconf = os.path.join(testdir, 'etc', idpname, 'ipsilon.conf')
    newconf = ConfigParser.ConfigParser()
    with open(ipsilonconf, 'r') as f:
        newconf.readfp(f)
    with open(ipsilonconf, 'w+') as f:
        newconf.set('global', 'admin.config.db',
                    '"configfile://%s"' % adminconf)
        newconf.write(f)

    os.remove(os.path.join(testdir, 'lib', idpname, 'adminconfig.sqlite'))


class IpsilonTest(IpsilonTestBase):

    def __init__(self):
        super(IpsilonTest, self).__init__('fconf', __file__)

    def setup_servers(self, env=None):
        print "Installing IDP server"
        idp = self.generate_profile(idp_g, idp_a, idpname, idpaddr, idpport)
        idpconf = self.setup_idp_server(idp, idpname, idpaddr, idpport, env)

        print "Installing SP server"
        sp = self.generate_profile(sp_g, sp_a, spname, spaddr, spport)
        spconf = self.setup_sp_server(sp, spname, spaddr, spport, env)
        fixup_sp_httpd(os.path.dirname(spconf))

        fixup_idp_conf(self.testdir)

        print "Starting IDP's httpd server"
        self.start_http_server(idpconf, env)

        print "Starting SP's httpd server"
        self.start_http_server(spconf, env)


if __name__ == '__main__':

    user = pwd.getpwuid(os.getuid())[0]

    sess = HttpSessions()
    sess.add_server(idpname, 'http://127.0.0.10:45080', user, 'ipsilon')
    sess.add_server(spname, 'http://127.0.0.11:45081')

    print "test1: Access SP Protected Area ...",
    try:
        page = sess.fetch_page(idpname, 'http://127.0.0.11:45081/sp/')
        page.expected_value('text()', 'WORKS!')
    except ValueError, e:
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"
