#!/usr/bin/python
#
# Copyright (C) 2014  Simo Sorce <simo@redhat.com>
#
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


from helpers.common import IpsilonTestBase  # pylint: disable=relative-import
from helpers.http import HttpSessions  # pylint: disable=relative-import
import os
import pwd
import sys
import inspect
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
         'openid': 'yes',
         'openid_extensions': 'Attribute Exchange,Simple Registration,Teams',
         'pam': 'no',
         'krb': 'no',
         'ipa': 'no',
         'server_debugging': 'True'}


def fixup_sp_httpd(httpdir, testdir):
    client_wsgi = """

WSGIScriptAlias / ${TESTDIR}/blobs/openid_app.py

<Directory ${TESTDIR}/blobs>
    Require all granted
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
        conf = self.setup_http(name, addr, port)
        testdir = os.path.dirname(os.path.abspath(inspect.getfile(
            inspect.currentframe())))
        fixup_sp_httpd(os.path.dirname(conf), testdir)

        print "Starting SP's httpd server"
        self.start_http_server(conf, env)


if __name__ == '__main__':

    idpname = 'idp1'
    sp1name = 'sp1'
    user = pwd.getpwuid(os.getuid())[0]

    sess = HttpSessions()
    sess.add_server(idpname, 'http://127.0.0.10:45080', user, 'ipsilon')
    sess.add_server(sp1name, 'http://127.0.0.11:45081')

    print "openid: Authenticate to IDP ...",
    try:
        sess.auth_to_idp(idpname)
    except Exception as e:  # pylint: disable=broad-except
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "openid: Run OpenID Protocol ...",
    try:
        page = sess.fetch_page(idpname,
                               'http://127.0.0.11:45081/?extensions=NO')
        page.expected_value('text()', 'SUCCESS, WITHOUT EXTENSIONS')
    except ValueError as e:
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "openid: Run OpenID Protocol with extensions ...",
    try:
        page = sess.fetch_page(idpname,
                               'http://127.0.0.11:45081/?extensions=YES')
        page.expected_value('text()', 'SUCCESS, WITH EXTENSIONS')
    except ValueError as e:
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"
