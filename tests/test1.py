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


from helpers import http  # pylint: disable=relative-import
import os
import pwd
import sys


if __name__ == '__main__':
    basedir = sys.argv[1]

    idpname = 'idp1'
    spname = 'sp1'
    user = pwd.getpwuid(os.getuid())[0]

    sess = http.HttpSessions()
    sess.add_server(idpname, 'http://127.0.0.10:45080', user, 'ipsilon')
    sess.add_server(spname, 'http://127.0.0.11:45081')

    print "test1: Authenticate to IDP ...",
    try:
        sess.auth_to_idp(idpname)
    except Exception, e:  # pylint: disable=broad-except
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "test1: Add SP Metadata to IDP ...",
    try:
        sess.add_sp_metadata(idpname, spname)
    except Exception, e:  # pylint: disable=broad-except
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "test1: Access SP Protected Area ...",
    try:
        page = sess.fetch_page(idpname, 'http://127.0.0.11:45081/sp/')
        page.expected_value('text()', 'WORKS!')
    except ValueError, e:
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"
