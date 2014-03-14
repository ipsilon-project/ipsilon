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
import sys


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
    parser.add_argument('--ipa', choices=['yes', 'no'], default='yes',
                        help='Detect and use an IPA server for authentication')

    lms = []

    for plugin_group in plugins:
        group = parser.add_argument_group(plugin_group)
        for plugin_name in plugins[plugin_group]:
            plugin = plugins[plugin_group][plugin_name]
            if plugin.ptype == 'login':
                lms.append(plugin.name)
            plugin.install_args(group)

    args = vars(parser.parse_args())

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
    found_plugins = find_plugins()
    opts = parse_args(found_plugins)
    print opts
