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

import logging
import pwd
import os
import socket
import subprocess
import sys


IPA_CONFIG_FILE = '/etc/ipa/default.conf'
HTTPD_IPA_KEYTAB = '/etc/httpd/conf/ipa.keytab'
IPA_COMMAND = '/usr/bin/ipa'
IPA_GETKEYTAB = '/usr/sbin/ipa-getkeytab'
HTTPD_USER = 'apache'

NO_CREDS_FOR_KEYTAB = """
Valid IPA admin credentials are required to get a keytab.
Please kinit with a pivileged user like 'admin' and retry.
"""

FAILED_TO_GET_KEYTAB = """
A pre-existing keytab was not found and it was not possible to
successfully retrieve a new keytab for the IPA server. Please
manually provide a keytab or resolve the error that cause this
failure (see logs) and retry.
"""


class Installer(object):

    def __init__(self):
        self.name = 'ipa'
        self.ptype = 'helper'
        self.logger = None
        self.realm = None
        self.domain = None
        self.server = None

    def install_args(self, group):
        group.add_argument('--ipa', choices=['yes', 'no', 'auto'],
                           default='auto',
                           help='Helper for IPA joined machines')

    def conf_init(self, opts):
        logger = self.logger
        # Do a simple check to see if machine is ipa joined
        if not os.path.exists(IPA_CONFIG_FILE):
            logger.info('No IPA configuration file. Skipping ipa helper...')
            if opts['ipa'] == 'yes':
                raise Exception('No IPA installation found!')
            return

        # Get config vars from ipa file
        try:
            from ipapython import config as ipaconfig

            ipaconfig.init_config()
            self.realm = ipaconfig.config.get_realm()
            self.domain = ipaconfig.config.get_domain()
            self.server = ipaconfig.config.get_server()

        except Exception, e:  # pylint: disable=broad-except
            logger.info('IPA tools installation found: [%s]', str(e))
            if opts['ipa'] == 'yes':
                raise Exception('No IPA installation found!')
            return

    def get_keytab(self, opts):
        logger = self.logger
        # Check if we have need ipa tools
        if not os.path.exists(IPA_GETKEYTAB):
            logger.info('ipa-getkeytab missing. Will skip keytab creation.')
            if opts['ipa'] == 'yes':
                raise Exception('No IPA tools found!')

        # Check if we already have a keytab for HTTP
        if 'krb_httpd_keytab' in opts:
            msg = "Searching for keytab in: %s" % opts['krb_httpd_keytab']
            print >> sys.stdout, msg,
            if os.path.exists(opts['krb_httpd_keytab']):
                print >> sys.stdout, "... Found!"
                return
            else:
                print >> sys.stdout, "... Not found!"

        msg = "Searching for keytab in: %s" % HTTPD_IPA_KEYTAB
        print >> sys.stdout, msg,
        if os.path.exists(HTTPD_IPA_KEYTAB):
            opts['krb_httpd_keytab'] = HTTPD_IPA_KEYTAB
            print >> sys.stdout, "... Found!"
            return
        else:
            print >> sys.stdout, "... Not found!"

        us = socket.gethostname()
        princ = 'HTTP/%s@%s' % (us, self.realm)

        # Check we have credentials to access server (for keytab)
        from ipapython import ipaldap
        from ipalib import errors as ipaerrors

        for srv in self.server:
            msg = "Testing access to server: %s" % srv
            print >> sys.stdout, msg,
            try:
                server = srv
                c = ipaldap.IPAdmin(host=server)
                c.do_sasl_gssapi_bind()
                del c
                print >> sys.stdout, "... Succeeded!"
                break
            except ipaerrors.ACIError, e:
                # usually this error is returned when we have no
                # good credentials, ask the user to kinit and retry
                print >> sys.stderr, NO_CREDS_FOR_KEYTAB
                logger.error('Invalid credentials: [%s]', repr(e))
                raise Exception('Invalid credentials: [%s]', str(e))
            except Exception, e:  # pylint: disable=broad-except
                # for other exceptions let's try to fail later
                pass

        try:
            subprocess.check_output([IPA_COMMAND, 'service-add', princ],
                                    stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError, e:
            # hopefully this means the service already exists
            # otherwise we'll fail later again
            logger.info('Error trying to create HTTP service:')
            logger.info('Cmd> %s\n%s', e.cmd, e.output)

        try:
            msg = "Trying to fetch keytab[%s] for %s" % (
                  opts['krb_httpd_keytab'], princ)
            print >> sys.stdout, msg,
            subprocess.check_output([IPA_GETKEYTAB,
                                     '-s', server, '-p', princ,
                                     '-k', opts['krb_httpd_keytab']],
                                    stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError, e:
            # unfortunately this one is fatal
            print >> sys.stderr, FAILED_TO_GET_KEYTAB
            logger.info('Error trying to get HTTP keytab:')
            logger.info('Cmd> %s\n%s', e.cmd, e.output)
            raise Exception('Missing keytab: [%s]' % str(e))

        # Fixup permissions so only the ipsilon user can read these files
        pw = pwd.getpwnam(HTTPD_USER)
        os.chown(opts['krb_httpd_keytab'], pw.pw_uid, pw.pw_gid)

    def configure_server(self, opts):
        if opts['ipa'] != 'yes' and opts['ipa'] != 'auto':
            return

        self.logger = logging.getLogger()

        self.conf_init(opts)

        self.get_keytab(opts)

        # Forcibly use krb then pam modules
        if 'lm_order' not in opts:
            opts['lm_order'] = []
        opts['krb'] = 'yes'
        if 'krb' not in opts['lm_order']:
            opts['lm_order'].insert(0, 'krb')
        opts['pam'] = 'yes'
        if 'pam' not in opts['lm_order']:
            opts['lm_order'].append('pam')
