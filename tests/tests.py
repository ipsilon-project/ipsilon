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

import argparse
from datetime import datetime
import inspect
from ipsilon.util import plugin
import logging
import os
import sys
import subprocess
import traceback


logger = None


class Tests(object):

    def __init__(self):
        p = plugin.Plugins()
        (pathname, dummy) = os.path.split(inspect.getfile(Tests))
        self.plugins = p.get_plugins(pathname, 'IpsilonTest')


def parse_args():
    parser = argparse.ArgumentParser(description='Ipsilon Tests Environment')
    parser.add_argument('--path', default='%s/testdir' % os.getcwd(),
                        help="Directory in which tests are run")
    parser.add_argument('--test', default='test1',
                        help="The test to run")
    parser.add_argument('--wrappers', default='auto',
                        choices=['yes', 'no', 'auto'],
                        help="Run the tests with socket wrappers")

    return vars(parser.parse_args())


def try_wrappers(base, wrappers):
    if wrappers == 'no':
        return {}

    pkgcfg = subprocess.Popen(['pkg-config', '--exists', 'socket_wrapper'])
    pkgcfg.wait()
    if pkgcfg.returncode != 0:
        if wrappers == 'auto':
            return {}
        else:
            raise ValueError('Socket Wrappers not available')

    wrapdir = os.path.join(base, 'wrapdir')
    os.mkdir(wrapdir)

    wenv = {'LD_PRELOAD': 'libsocket_wrapper.so',
            'SOCKET_WRAPPER_DIR': wrapdir,
            'SOCKET_WRAPPER_DEFAULT_IFACE': '9'}

    return wenv


if __name__ == '__main__':

    args = parse_args()

    tests = Tests()
    if args['test'] not in tests.plugins:
        print >> sys.stderr, "Unknown test [%s]" % args['test']
        sys.exit(1)
    test = tests.plugins[args['test']]

    if not os.path.exists(args['path']):
        os.makedirs(args['path'])

    test.setup_base(args['path'], test)

    env = try_wrappers(test.testdir, args['wrappers'])
    env['PYTHONPATH'] = test.rootdir

    try:
        test.setup_servers(env)

        code = test.run(env)
        if code:
            sys.exit(code)
    except Exception, e:  # pylint: disable=broad-except
        print >> sys.stderr, "Error: %s" % repr(e)
        traceback.print_exc(None, sys.stderr)
        sys.exit(1)
    finally:
        test.wait()

    print "FINISHED"
