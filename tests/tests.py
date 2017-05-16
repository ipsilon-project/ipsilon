#!/usr/bin/python
#
# Copyright (C) 2014-2017 Ipsilon project Contributors, for license see COPYING

from __future__ import print_function

__requires__ = ['sqlalchemy >= 0.8']
import pkg_resources  # pylint: disable=unused-import

import argparse
from ipsilon.util import plugin
import os
import sys
import subprocess
from helpers.common import WRAP_HOSTNAME  # pylint: disable=relative-import
from helpers.control import TC  # pylint: disable=relative-import


logger = None


VERBOSE_SHOWTESTS = 1
VERBOSE_SHOWCASES = 2
VERBOSE_SHOWOUTPUT = 3


TEST_RESULT_SUCCESS = 0
TEST_RESULT_SKIP = 1
TEST_RESULT_FAIL = 2
TEST_RESULT_EXCEPTION = 3
TEST_RESULT_SETUP_FAILED = 4


def get_tests():
    p = plugin.Plugins()
    (pathname, _) = os.path.split(os.path.realpath(__file__))
    return p.get_plugins(pathname, 'IpsilonTest')


def parse_args():
    parser = argparse.ArgumentParser(description='Ipsilon Tests Environment')
    parser.add_argument('--results-header', default='Test results:',
                        help='Test results header')
    parser.add_argument('--path', default='%s/testdir' % os.getcwd(),
                        help="Directory in which tests are run")
    parser.add_argument('--fail-on-first-error', '-x', action='store_true',
                        help='Abort test run on first test failure')
    parser.add_argument('--test', action='append', default=None,
                        help="Add a test to run")
    parser.add_argument('--list-tests', '-L', action='store_true',
                        help='List all available tests')
    parser.add_argument('--no-overview', '-q', action='store_true',
                        help='Suppress final summary')
    parser.add_argument('--verbose', '-v', action='count',
                        help='Increase verbosity')
    parser.add_argument('--wrappers', default='auto',
                        choices=['yes', 'no', 'auto'],
                        help="Run the tests with socket wrappers")

    return vars(parser.parse_args())


def try_wrappers(base, wrappers, allow_wrappers):
    if wrappers == 'no' or not allow_wrappers:
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


def run_test(testname, test, args):
    supported = test.platform_supported()
    if supported is not None:
        return (TEST_RESULT_SKIP, supported)
    if args['verbose'] <= VERBOSE_SHOWOUTPUT:
        devnull = open(os.devnull, 'w')
        test.stdout = devnull
        test.stderr = devnull

    if args['verbose'] >= VERBOSE_SHOWCASES:
        test.print_cases = True

    test.setup_base(args['path'], test)

    env = try_wrappers(test.testdir, args['wrappers'], test.allow_wrappers)
    env['PYTHONPATH'] = test.rootdir
    env['TESTDIR'] = test.testdir

    results = []
    post_setup = False
    TC.store_results(results)
    try:
        test.setup_servers(env)
        post_setup = True

        code, results = test.run(env)
        if code:
            return (TEST_RESULT_FAIL, code, results)
    except Exception as e:  # pylint: disable=broad-except
        if post_setup:
            return (TEST_RESULT_EXCEPTION, e, results)
        else:
            return (TEST_RESULT_SETUP_FAILED, test.current_setup_step)
    finally:
        test.wait()

    return (TEST_RESULT_SUCCESS, results)


def result_to_str(result):
    if result[0] == TEST_RESULT_SUCCESS:
        return 'Test passed'
    elif result[0] == TEST_RESULT_SKIP:
        return 'Test skipped: %s' % result[1]
    elif result[0] == TEST_RESULT_FAIL:
        return 'Test failed with code %i' % result[1]
    elif result[0] == TEST_RESULT_EXCEPTION:
        return 'Test failed with error: %s' % repr(result[1])
    elif result[0] == TEST_RESULT_SETUP_FAILED:
        return 'Test setup failed at step: %s' % result[1]
    else:
        return 'Unknown test result %s' % result[0]


def result_is_fail(result):
    return result[0] not in (TEST_RESULT_SUCCESS, TEST_RESULT_SKIP)


def main():
    args = parse_args()

    tests = get_tests()
    if args['list_tests']:
        for testname in tests.keys():
            print(testname)
        sys.exit(0)

    if args['test'] is None:
        args['test'] = tests.keys()
    unknown_tests = False
    for test in args['test']:
        if test not in tests:
            unknown_tests = True
            print("Unknown test [%s]" % test, file=sys.stderr)
    if unknown_tests:
        sys.exit(1)
    args['test'] = set(args['test'])

    if not os.path.exists(args['path']):
        os.makedirs(args['path'])

    test_results = {}

    for test in args['test']:
        if args['verbose'] >= VERBOSE_SHOWTESTS:
            print('Running test %s' % test)
        result = run_test(test, tests[test], args)
        test_results[test] = result

        if args['verbose'] >= VERBOSE_SHOWTESTS:
            print(result_to_str(result))

        if args['fail_on_first_error'] and result_is_fail(result):
            break

    if not args['no_overview']:
        print(args['results_header'])
        for test in test_results:
            print('{:15s} {}'.format(test, result_to_str(test_results[test])))

    if any(result_is_fail(result)
           for result in test_results.values()):
        sys.exit(1)


if __name__ == '__main__':
    main()
