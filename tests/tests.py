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
import ConfigParser
from datetime import datetime
import logging
import os
import pwd
import shutil
import signal
import subprocess
import sys
from string import Template


logger = None


def parse_args():
    parser = argparse.ArgumentParser(description='Ipsilon Tests Environment')
    parser.add_argument('--path', default='%s/testdir' % os.getcwd(),
                        help="Directory in which tests are run")
    parser.add_argument('--test', default='test1',
                        help="The test to run")

    return vars(parser.parse_args())


def openlogs(path, test):
    global logger  # pylint: disable=W0603
    logger = logging.getLogger()
    try:
        datestr = datetime.now().strftime("%Y-%m-%d_%H:%M:%S")
        filename = '%s/test-%s-%s.log' % (path, test, datestr)
        lh = logging.FileHandler(filename)
    except IOError, e:
        print >> sys.stderr, 'Unable to open %s (%s)' % (filename, str(e))
        lh = logging.StreamHandler(sys.stderr)
    formatter = logging.Formatter('[%(asctime)s] %(message)s')
    lh.setFormatter(formatter)
    logger.addHandler(lh)
    logger.setLevel(logging.DEBUG)


def force_remove(op, name, info):
    os.chmod(name, 0700)
    os.remove(name)


def setup_http(httpdir, addr, port):
    os.mkdir(httpdir)
    os.mkdir(httpdir + '/conf.d')
    os.mkdir(httpdir + '/html')
    os.mkdir(httpdir + '/logs')
    os.symlink('/etc/httpd/modules', httpdir + '/modules')

    with open('tests/httpd.conf') as f:
        t = Template(f.read())
        text = t.substitute({'HTTPROOT': httpdir,
                             'HTTPADDR': addr, 'HTTPPORT': port})
    with open(httpdir + '/httpd.conf', 'w+') as f:
        f.write(text)


def setup_test(path, test):
    profile = 'tests/%s.cfg' % test
    if not os.path.exists(profile):
        raise ValueError('Unrecognized test name [%s]' % test)

    opts = {}
    config = ConfigParser.ConfigParser()
    config.read(profile)
    if 'tests' not in config.sections():
        raise ValueError('Missing [tests] in profile [%s]' % test)
    T = config.options('tests')
    for t in T:
        opts[t] = config.get('tests', t)

    base = '%s/%s' % (path, test)
    if os.path.exists(base):
        shutil.rmtree(base, onerror=force_remove)
    os.makedirs(base)
    shutil.copytree('templates', base + '/templates')
    os.mkdir(base + '/etc')
    os.mkdir(base + '/lib')
    os.mkdir(base + '/lib/' + test)
    os.mkdir(base + '/log')

    with open(profile) as f:
        t = Template(f.read())
        text = t.substitute({'TESTDIR': base, 'ROOTDIR': os.getcwd(),
                             'TEST_USER': pwd.getpwuid(os.getuid())[0]})
    with open(base + '/profile.cfg', 'w+') as f:
        f.write(text)

    opts['basedir'] = base
    return opts


def generate_profile(profile, name):
    config = ConfigParser.ConfigParser()
    config.read(profile)

    global_section = '%s_globals' % name
    global_options = {}
    if global_section in config.sections():
        G = config.options(global_section)
        for g in G:
            global_options[g] = config.get(global_section, g)

    args_section = '%s_arguments' % name
    args_options = {}
    if args_section in config.sections():
        A = config.options(args_section)
        for a in A:
            args_options[a] = config.get(args_section, a)

    newconf = ConfigParser.ConfigParser()
    newconf.add_section('globals')
    for k in global_options.keys():
        newconf.set('globals', k, global_options[k])
    newconf.add_section('arguments')
    for k in args_options.keys():
        newconf.set('arguments', k, args_options[k])

    filename = os.path.join(os.path.dirname(profile), '%s_profile.cfg' % name)
    with open(filename, 'wb') as f:
        newconf.write(f)

    return filename


def fixup_sp_httpd(httpdir):
    location = """

Alias /sp ${HTTPDIR}/sp

<Directory ${HTTPDIR}/sp>
    Require all granted
</Directory>
"""
    index = """WORKS!"""

    t = Template(location)
    text = t.substitute({'HTTPDIR': httpdir})
    with open(httpdir + '/conf.d/ipsilon-saml.conf', 'a') as f:
        f.write(text)

    os.mkdir(httpdir + '/sp')
    with open(httpdir + '/sp/index.html', 'w') as f:
        f.write(index)

if __name__ == '__main__':

    args = parse_args()

    if not os.path.exists(args['path']):
        os.makedirs(args['path'])
    openlogs(args['path'], args['test'])

    options = setup_test(args['path'], args['test'])
    basedir = options['basedir']

    env={'PYTHONPATH':'./'}
    srvs = []
    try:
        for h in options['servers'].split(','):
            sname, saddr, sport = h.split(':')
            basehttpdir = '%s/%s' % (basedir, sname)
            setup_http(basehttpdir, saddr, sport)

            sprofile = generate_profile('%s/profile.cfg' % basedir, sname)
            p = subprocess.Popen(['./ipsilon/install/ipsilon-server-install',
                                  '--config-profile=%s' % sprofile], env=env,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            stdout, stderr = p.communicate()
            logger.error(stderr)
            logger.info(stdout)
            if p.returncode:
                sys.exit(p.returncode)

            os.symlink('%s/ipsilon' % os.getcwd(),
                       '%s/lib/%s/ipsilon' % (basedir, sname))

            print "Starting httpd server in %s" % basehttpdir
            srv = subprocess.Popen(['/usr/sbin/httpd', '-DFOREGROUND',
                                    '-f', basehttpdir + '/httpd.conf'],
                                   env=env, preexec_fn=os.setsid)
            srvs.append(srv)

        for h in options['clients'].split(','):
            sname, saddr, sport = h.split(':')
            basehttpdir = '%s/%s' % (basedir, sname)
            setup_http(basehttpdir, saddr, sport)

            sprofile = generate_profile('%s/profile.cfg' % basedir, sname)
            p = subprocess.Popen(['./ipsilon/install/ipsilon-client-install',
                                  '--config-profile=%s' % sprofile], env=env,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            stdout, stderr = p.communicate()
            logger.error(stderr)
            logger.info(stdout)
            if p.returncode:
                sys.exit(p.returncode)

            fixup_sp_httpd(basehttpdir)

            print "Starting httpd server in %s" % basehttpdir
            srv = subprocess.Popen(['/usr/sbin/httpd', '-DFOREGROUND',
                                    '-f', basehttpdir + '/httpd.conf'],
                                   env=env, preexec_fn=os.setsid)
            srvs.append(srv)

        if os.path.exists('tests/%s.py' % args['test']):
            code = subprocess.call(['./tests/%s.py' % args['test'], basedir],
                                   env=env)
            if code:
                sys.exit(code)
    except Exception:  # pylint: disable=broad-except
        sys.exit(1)
    finally:
        for srv in srvs:
            os.killpg(srv.pid, signal.SIGTERM)

    print "FINISHED"
