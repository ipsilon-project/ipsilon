#!/usr/bin/python
#
# Copyright (C) 2015 Ipsilon project Contributors, for license see COPYING

from helpers.common import IpsilonTestBase  # pylint: disable=relative-import
from helpers.common import WRAP_HOSTNAME  # pylint: disable=relative-import
from helpers.common import TESTREALM  # pylint: disable=relative-import
from helpers.http import HttpSessions  # pylint: disable=relative-import
from ipsilon.tools.saml2metadata import SAML2_NAMEID_MAP
import os
import pwd
import sys
import re
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
         'gssapi': 'yes',
         'gssapi_httpd_keytab': '${TESTDIR}/${HTTP_KTNAME}',
         'ipa': 'no',
         'server_debugging': 'True'}


sp_g = {'HTTPDCONFD': '${TESTDIR}/${NAME}/conf.d',
        'SAML2_TEMPLATE': '${TESTDIR}/templates/install/saml2/sp.conf',
        'SAML2_CONFFILE': '${TESTDIR}/${NAME}/conf.d/ipsilon-saml.conf',
        'SAML2_HTTPDIR': '${TESTDIR}/${NAME}/saml2'}


sp_a = {'hostname': '${ADDRESS}:${PORT}',
        'saml_idp_metadata': 'http://%s:45080/idp1/saml2/metadata' %
        WRAP_HOSTNAME,
        'saml_secure_setup': 'False',
        'saml_auth': '/sp',
        'saml_nameid': '${NAMEID}',
        'httpd_user': '${TEST_USER}'}


def generate_sp_list():
    splist = []
    spport = 45081

    for nameid in SAML2_NAMEID_MAP.keys():
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
    Require all granted
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

        print "Installing KDC server"
        kdcenv = self.setup_kdc(env)

        print "Creating principals and keytabs"
        self.setup_keys(kdcenv)

        print "Getting a TGT"
        self.kinit_keytab(kdcenv)

        print "Installing IDP server"
        name = 'idp1'
        addr = WRAP_HOSTNAME
        port = '45080'
        idp = self.generate_profile(idp_g, idp_a, name, addr, port)
        conf = self.setup_idp_server(idp, name, addr, port, env)

        print "Starting IDP's httpd server"
        env.update(kdcenv)
        self.start_http_server(conf, env)

        for spdata in generate_sp_list():
            nameid = spdata['nameid']
            addr = spdata['addr']
            port = spdata['port']
            print "Installing SP server %s" % nameid
            sp_prof = self.generate_profile(
                sp_g, sp_a, nameid, addr, str(port), nameid
            )
            conf = self.setup_sp_server(sp_prof, nameid, addr, str(port), env)
            fixup_sp_httpd(os.path.dirname(conf))

            print "Starting SP's httpd server"
            self.start_http_server(conf, env)


if __name__ == '__main__':

    idpname = 'idp1'
    user = pwd.getpwuid(os.getuid())[0]

    expected = {
        'x509':        False,   # not supported
        'transient':   True,
        'persistent':  True,
        'windows':     False,   # not supported
        'encrypted':   False,   # not supported
        'kerberos':    True,
        'email':       True,
        'unspecified': True,
        'entity':      False,   # not supported
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
        spurl = 'http://%s:%s' % (sp['addr'], sp['port'])
        sess = HttpSessions()
        sess.add_server(idpname, 'http://%s:45080' % WRAP_HOSTNAME, user,
                        'ipsilon')
        sess.add_server(spname, spurl)

        print ""
        print "testnameid: Testing NameID format %s ..." % spname

        if spname == 'kerberos':
            krb = True

        print "testnameid: Authenticate to IDP ...",
        try:
            sess.auth_to_idp(idpname, krb=krb)
        except Exception, e:  # pylint: disable=broad-except
            print >> sys.stderr, " ERROR: %s" % repr(e)
            sys.exit(1)
        print " SUCCESS"

        print "testnameid: Add SP Metadata to IDP ...",
        try:
            sess.add_sp_metadata(idpname, spname)
        except Exception, e:  # pylint: disable=broad-except
            print >> sys.stderr, " ERROR: %s" % repr(e)
            sys.exit(1)
        print " SUCCESS"

        print "testnameid: Set supported Name ID formats ...",
        try:
            sess.set_sp_default_nameids(idpname, spname, [spname])
        except Exception, e:  # pylint: disable=broad-except
            print >> sys.stderr, " ERROR: %s" % repr(e)
            sys.exit(1)
        print " SUCCESS"

        print "testnameid: Access SP Protected Area ...",
        try:
            page = sess.fetch_page(idpname, '%s/sp/' % spurl)
            if not re.match(expected_re[spname], page.text):
                raise ValueError(
                    'page did not contain expression %s' %
                    expected_re[spname]
                )
        except ValueError, e:
            if expected[spname]:
                print >> sys.stderr, " ERROR: %s" % repr(e)
                sys.exit(1)
            print " OK, EXPECTED TO FAIL"
        else:
            print " SUCCESS"

        print "testnameid: Try authentication failure ...",
        newsess = HttpSessions()
        newsess.add_server(idpname, 'http://%s:45080' % WRAP_HOSTNAME,
                           user, 'wrong')
        try:
            newsess.auth_to_idp(idpname)
            print >> sys.stderr, " ERROR: Authentication should have failed"
            sys.exit(1)
        except Exception, e:  # pylint: disable=broad-except
            print " SUCCESS"

    # Ensure that transient names change with each authentication
    sp = get_sp_by_nameid(sp_list, 'transient')
    spname = sp['nameid']
    spurl = 'http://%s:%s' % (sp['addr'], sp['port'])

    print ""
    print "testnameid: Testing NameID format %s ..." % spname

    ids = []
    for i in xrange(4):
        sess = HttpSessions()
        sess.add_server(idpname, 'http://%s:45080' % WRAP_HOSTNAME,
                        user, 'ipsilon')
        sess.add_server(spname, spurl)
        print "testnameid: Authenticate to IDP ...",
        try:
            sess.auth_to_idp(idpname)
        except Exception, e:  # pylint: disable=broad-except
            print >> sys.stderr, " ERROR: %s" % repr(e)
            sys.exit(1)
        else:
            print " SUCCESS"

        print "testnameid: Access SP ...",
        try:
            page = sess.fetch_page(idpname, '%s/sp/' % spurl)
            t1 = page.text
        except ValueError, e:
            print >> sys.stderr, " ERROR: %s" % repr(e)
            sys.exit(1)
        else:
            print " SUCCESS"

        print "testnameid: Access SP again ...",
        try:
            page = sess.fetch_page(idpname, '%s/sp/' % spurl)
            t2 = page.text
        except ValueError, e:
            print >> sys.stderr, " ERROR: %s" % repr(e)
            sys.exit(1)
        else:
            print " SUCCESS"

        print "testnameid: Ensure ID is consistent between requests ...",
        if t1 != t2:
            print >> sys.stderr, " ERROR: New ID between reqeusts"
        else:
            print " SUCCESS"

        ids.append(t1)

    print "testnameid: Ensure uniqueness across sessions ...",
    if len(ids) != len(set(ids)):
        print >> sys.stderr, " ERROR: IDs are not unique between sessions"
        sys.exit(1)
    else:
        print " SUCCESS"

    # Ensure that persistent names remain the same with each authentication
    sp = get_sp_by_nameid(sp_list, 'persistent')
    spname = sp['nameid']
    spurl = 'http://%s:%s' % (sp['addr'], sp['port'])

    print ""
    print "testnameid: Testing NameID format %s ..." % spname

    ids = []
    for i in xrange(4):
        sess = HttpSessions()
        sess.add_server(idpname, 'http://%s:45080' % WRAP_HOSTNAME,
                        user, 'ipsilon')
        sess.add_server(spname, spurl)
        print "testnameid: Authenticate to IDP ...",
        try:
            sess.auth_to_idp(idpname)
        except Exception, e:  # pylint: disable=broad-except
            print >> sys.stderr, " ERROR: %s" % repr(e)
            sys.exit(1)
        else:
            print " SUCCESS"

        print "testnameid: Access SP ...",
        try:
            page = sess.fetch_page(idpname, '%s/sp/' % spurl)
            t1 = page.text
        except ValueError, e:
            print >> sys.stderr, " ERROR: %s" % repr(e)
            sys.exit(1)
        else:
            print " SUCCESS"

        print "testnameid: Access SP again ...",
        try:
            page = sess.fetch_page(idpname, '%s/sp/' % spurl)
            t2 = page.text
        except ValueError, e:
            print >> sys.stderr, " ERROR: %s" % repr(e)
            sys.exit(1)
        else:
            print " SUCCESS"

        print "testnameid: Ensure ID is consistent between requests ...",
        if t1 != t2:
            print >> sys.stderr, " ERROR: New ID between reqeusts"
        else:
            print " SUCCESS"

        ids.append(t1)

    print "testnameid: Ensure same ID across sessions ...",
    if len(set(ids)) != 1:
        print >> sys.stderr, " ERROR: IDs are not the same between sessions"
        sys.exit(1)
    else:
        print " SUCCESS"
