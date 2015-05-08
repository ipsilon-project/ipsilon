#!/usr/bin/python
#
# Copyright (C) 2014 Ipsilon project Contributors, for license see COPYING

import argparse
import inspect
from ipsilon.util import plugin
import os
import sys
import subprocess
import time
import traceback
from helpers.common import WRAP_HOSTNAME  # pylint: disable=relative-import


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

    pkgcfg = subprocess.Popen(['pkg-config', '--exists', 'nss_wrapper'])
    pkgcfg.wait()
    if pkgcfg.returncode != 0:
        if wrappers == 'auto':
            return {}
        else:
            raise ValueError('Nss Wrappers not available')

    wrapdir = os.path.join(base, 'wrapdir')
    os.mkdir(wrapdir)

    hosts_file = os.path.join(base, 'hosts')
    with open(hosts_file, 'w+') as f:
        f.write('127.0.0.9 %s\n' % WRAP_HOSTNAME)

    wenv = {'LD_PRELOAD': 'libsocket_wrapper.so libnss_wrapper.so',
            'SOCKET_WRAPPER_DIR': wrapdir,
            'SOCKET_WRAPPER_DEFAULT_IFACE': '9',
            'SOCKET_WRAPPER_DEBUGLEVEL': '1',
            'NSS_WRAPPER_HOSTNAME': WRAP_HOSTNAME,
            'NSS_WRAPPER_HOSTS': hosts_file}

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
    env['TESTDIR'] = test.testdir

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

    # Wait until all of the sockets are closed by the OS
    time.sleep(0.5)
    print "FINISHED"
