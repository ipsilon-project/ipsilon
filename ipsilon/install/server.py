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

from ipsilon.login.common import LoginMgrsInstall
from ipsilon.providers.common import ProvidersInstall
import argparse
import cherrypy
import logging
import os
import shutil
import socket
import sys
import time


TEMPLATES = '/usr/share/ipsilon/templates/install'
CONFDIR = '/etc/ipsilon'
HTTPDCONFD = '/etc/httpd/conf.d'


class ConfigurationError(Exception):

    def __init__(self, message):
        super(ConfigurationError, self).__init__(message)
        self.message = message

    def __str__(self):
        return repr(self.message)


#Silence cherrypy logging to screen
cherrypy.log.screen = False

# Regular logging
LOGFILE = '/var/log/ipsilon-install.log'
logger = logging.getLogger()


def openlogs():
    global logger  # pylint: disable=W0603
    if os.path.isfile(LOGFILE):
        try:
            created = '%s' % time.ctime(os.path.getctime(LOGFILE))
            shutil.move(LOGFILE, '%s.%s' % (LOGFILE, created))
        except IOError:
            pass
    logger = logging.getLogger()
    try:
        lh = logging.FileHandler(LOGFILE)
    except IOError, e:
        print >> sys.stderr, 'Unable to open %s (%s)' % (LOGFILE, str(e))
        lh = logging.StreamHandler(sys.stderr)
    formatter = logging.Formatter('[%(asctime)s] %(message)s')
    lh.setFormatter(formatter)
    logger.addHandler(lh)


def install(plugins, args):
    logger.info('Installation initiated')
    now = time.strftime("%Y%m%d%H%M%S", time.gmtime())

    logger.info('Installing default config files')
    ipsilon_conf = os.path.join(CONFDIR, 'ipsilon.conf')
    idp_conf = os.path.join(CONFDIR, 'idp.conf')
    httpd_conf = os.path.join(HTTPDCONFD, 'idp.conf')
    if os.path.exists(ipsilon_conf):
        shutil.move(ipsilon_conf, '%s.bakcup.%s' % (ipsilon_conf, now))
    if os.path.exists(idp_conf):
        shutil.move(idp_conf, '%s.backup.%s' % (idp_conf, now))
    shutil.copy(os.path.join(TEMPLATES, 'ipsilon.conf'), CONFDIR)
    shutil.copy(os.path.join(TEMPLATES, 'idp.conf'), CONFDIR)
    if not os.path.exists(httpd_conf):
        os.symlink(idp_conf, httpd_conf)
    # Load the cherrypy config from the newly installed file so
    # that db paths and all is properly set before configuring
    # components
    cherrypy.config.update(ipsilon_conf)

    # Move pre-existing admin db away
    admin_db = cherrypy.config['admin.config.db']
    if os.path.exists(admin_db):
        shutil.move(admin_db, '%s.backup.%s' % (admin_db, now))

    logger.info('Configuring login managers')
    for plugin_name in args['lm_order']:
        plugin = plugins['Login Managers'][plugin_name]
        plugin.configure(args)

    logger.info('Configuring Authentication Providers')
    for plugin_name in plugins['Auth Providers']:
        plugin = plugins['Auth Providers'][plugin_name]
        plugin.configure(args)


def uninstall(plugins, args):
    logger.info('Uninstallation initiated')
    raise Exception('Not Implemented')


def find_plugins():
    plugins = {
        'Login Managers': LoginMgrsInstall().plugins,
        'Auth Providers': ProvidersInstall().plugins
    }
    return plugins


def parse_args(plugins):
    parser = argparse.ArgumentParser(description='Ipsilon Install Options')
    parser.add_argument('--version',
                        action='version', version='%(prog)s 0.1')
    parser.add_argument('-o', '--login-managers-order', dest='lm_order',
                        help='Comma separated list of login managers')
    parser.add_argument('--hostname',
                        help="Machine's fully qualified host name")
    parser.add_argument('--ipa', choices=['yes', 'no'], default='yes',
                        help='Detect and use an IPA server for authentication')
    parser.add_argument('--uninstall', action='store_true',
                        help="Uninstall the server and all data")

    lms = []

    for plugin_group in plugins:
        group = parser.add_argument_group(plugin_group)
        for plugin_name in plugins[plugin_group]:
            plugin = plugins[plugin_group][plugin_name]
            if plugin.ptype == 'login':
                lms.append(plugin.name)
            plugin.install_args(group)

    args = vars(parser.parse_args())

    if not args['hostname']:
        args['hostname'] = socket.getfqdn()

    if len(args['hostname'].split('.')) < 2:
        raise ConfigurationError('Hostname: %s is not a FQDN')

    if args['lm_order'] is None:
        args['lm_order'] = []
        for name in lms:
            if args[name] == 'yes':
                args['lm_order'].append(name)
    else:
        args['lm_order'] = args['lm_order'].split(',')

    if len(args['lm_order']) == 0:
        #force the basic pam provider if nothing else is selected
        if 'pam' not in args:
            parser.print_help()
            sys.exit(-1)
        args['lm_order'] = ['pam']
        args['pam'] = 'yes'

    return args

if __name__ == '__main__':
    opts = []
    out = 0
    openlogs()
    try:
        fplugins = find_plugins()
        opts = parse_args(fplugins)

        logger.setLevel(logging.DEBUG)

        logger.info('Intallation arguments:')
        for k in sorted(opts.iterkeys()):
            logger.info('%s: %s', k, opts[k])

        if 'uninstall' in opts and opts['uninstall'] is True:
            uninstall(fplugins, opts)

        install(fplugins, opts)
    except Exception, e:  # pylint: disable=broad-except
        logger.exception(e)
        if 'uninstall' in opts and opts['uninstall'] is True:
            print 'Uninstallation aborted.'
        else:
            print 'Installation aborted.'
        print 'See log file %s for details' % LOGFILE
        out = 1
    finally:
        if out == 0:
            if 'uninstall' in opts and opts['uninstall'] is True:
                print 'Uninstallation complete.'
            else:
                print 'Installation complete.'
    sys.exit(out)
