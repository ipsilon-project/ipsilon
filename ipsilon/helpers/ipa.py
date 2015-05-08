# Copyright (C) 2014 Ipsilon project Contributors, for license see COPYING

import logging
import pwd
import os
import socket
import subprocess

from ipsilon.helpers.common import EnvHelpersInstaller


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


class Installer(EnvHelpersInstaller):

    def __init__(self, *pargs):
        super(Installer, self).__init__()
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
            logger.info('IPA tools installation found: [%s]', e)
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
        if 'gssapi_httpd_keytab' in opts:
            msg = "Searching for keytab in: %s" % opts['gssapi_httpd_keytab']
            if os.path.exists(opts['gssapi_httpd_keytab']):
                logger.info(msg + "... Found!")
                return
            else:
                logger.info(msg + "... Not found!")

        msg = "Searching for keytab in: %s" % HTTPD_IPA_KEYTAB
        if os.path.exists(HTTPD_IPA_KEYTAB):
            opts['gssapi_httpd_keytab'] = HTTPD_IPA_KEYTAB
            logger.info(msg + "... Found!")
            return
        else:
            logger.info(msg + "... Not found!")

        us = socket.gethostname()
        princ = 'HTTP/%s@%s' % (us, self.realm)

        # Check we have credentials to access server (for keytab)
        from ipalib import api
        from ipalib import errors as ipaerrors

        api.bootstrap(context='ipsilon_installer')
        api.finalize()

        try:
            api.Backend.rpcclient.connect()
            logger.debug('Try RPC connection')
            api.Backend.rpcclient.forward('ping')
            logger.debug("... Succeeded!")
        except ipaerrors.KerberosError as e:
            logger.error('Invalid credentials: [%s]', repr(e))
            if api.Backend.rpcclient.isconnected():
                api.Backend.rpcclient.disconnect()
            raise Exception('Invalid credentials: [%s]' % e)
        except ipaerrors.PublicError as e:
            logger.error(
                'Cannot connect to the server due to generic error: %s', e)
            if api.Backend.rpcclient.isconnected():
                api.Backend.rpcclient.disconnect()
            raise Exception('Unable to connect to IPA server: %s' % e)

        # Specify an older version to work on nearly any master. Force is
        # set to True so a DNS A record is not required for adding the
        # service.
        try:
            api.Backend.rpcclient.forward(
                'service_add',
                unicode(princ),
                force=True,
                version=u'2.0',
            )
        except ipaerrors.DuplicateEntry:
            logger.debug('Principal %s already exists', princ)
        except ipaerrors.NotFound as e:
            logger.error('%s', e)
            raise Exception('%s' % e)
        except ipaerrors.ACIError as e:
            logger.error(NO_CREDS_FOR_KEYTAB)
            logger.debug('Invalid credentials: [%s]', repr(e))
            raise Exception('Invalid credentials: [%s]' % e)
        finally:
            server = api.Backend.rpcclient.api.env.server
            if api.Backend.rpcclient.isconnected():
                api.Backend.rpcclient.disconnect()

        try:
            msg = "Trying to fetch keytab[%s] for %s" % (
                  opts['gssapi_httpd_keytab'], princ)
            logger.info(msg)
            subprocess.check_output([IPA_GETKEYTAB,
                                     '-s', server, '-p', princ,
                                     '-k', opts['gssapi_httpd_keytab']],
                                    stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError, e:
            # unfortunately this one is fatal
            logger.error(FAILED_TO_GET_KEYTAB)
            logger.info('Error trying to get HTTP keytab:')
            logger.info('Cmd> %s\n%s', e.cmd, e.output)
            raise Exception('Missing keytab: [%s]' % e)

        # Fixup permissions so only the ipsilon user can read these files
        pw = pwd.getpwnam(HTTPD_USER)
        os.chown(opts['gssapi_httpd_keytab'], pw.pw_uid, pw.pw_gid)

    def configure_server(self, opts, changes):
        if opts['ipa'] != 'yes' and opts['ipa'] != 'auto':
            return
        if opts['ipa'] != 'yes' and opts['gssapi'] == 'no':
            return

        self.logger = logging.getLogger()

        self.conf_init(opts)

        self.get_keytab(opts)

        # Forcibly use gssapi then pam modules
        if 'lm_order' not in opts:
            opts['lm_order'] = []
        opts['gssapi'] = 'yes'
        if 'gssapi' not in opts['lm_order']:
            opts['lm_order'].insert(0, 'gssapi')
        opts['form'] = 'yes'
        if not any(lm in opts['lm_order'] for lm in ('form', 'pam')):
            opts['lm_order'].append('form')
