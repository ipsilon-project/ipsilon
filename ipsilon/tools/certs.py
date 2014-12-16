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

from subprocess import Popen
import os
import string


class Certificate(object):

    def __init__(self, path=None):
        self.subject = None
        self.key = None
        self.cert = None
        if path:
            self.path = path
        else:
            self.path = os.getcwd()

    def generate(self, prefix, subject):
        self.key = os.path.join(self.path, '%s.key' % prefix)
        self.cert = os.path.join(self.path, '%s.pem' % prefix)
        self.subject = '/CN=%s' % subject
        command = ['openssl',
                   'req', '-x509', '-batch', '-days', '1825',
                   '-newkey', 'rsa:2048', '-nodes', '-subj', self.subject,
                   '-keyout', self.key, '-out', self.cert]
        proc = Popen(command)
        proc.wait()

    def get_cert(self):
        if not self.cert:
            raise ValueError('Certificate unavailable')
        with open(self.cert, 'r') as f:
            cert = f.readlines()

        # poor man stripping of BEGIN/END lines
        if cert[0] == '-----BEGIN CERTIFICATE-----\n':
            cert = cert[1:]
        if cert[-1] == '-----END CERTIFICATE-----\n':
            cert = cert[:-1]

        return string.join(cert)
