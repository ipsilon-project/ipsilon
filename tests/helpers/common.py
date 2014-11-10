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


import ConfigParser
import io
import os
import pwd
import shutil
import signal
from string import Template
import subprocess


class IpsilonTestBase(object):

    def __init__(self, name, execname):
        self.name = name
        self.execname = execname
        self.rootdir = os.getcwd()
        self.testdir = None
        self.testuser = pwd.getpwuid(os.getuid())[0]
        self.processes = []

    def force_remove(self, op, name, info):
        os.chmod(name, 0700)
        os.remove(name)

    def setup_base(self, path, test):
        self.testdir = os.path.join(path, test.name)
        if os.path.exists(self.testdir):
            shutil.rmtree(self.testdir, onerror=self.force_remove)
        os.makedirs(self.testdir)
        shutil.copytree(os.path.join(self.rootdir, 'templates'),
                        os.path.join(self.testdir, 'templates'))
        os.mkdir(os.path.join(self.testdir, 'etc'))
        os.mkdir(os.path.join(self.testdir, 'lib'))
        os.mkdir(os.path.join(self.testdir, 'lib', test.name))
        os.mkdir(os.path.join(self.testdir, 'log'))

    def generate_profile(self, global_opts, args_opts, name, addr, port):
        newconf = ConfigParser.ConfigParser()
        newconf.add_section('globals')
        for k in global_opts.keys():
            newconf.set('globals', k, global_opts[k])
        newconf.add_section('arguments')
        for k in args_opts.keys():
            newconf.set('arguments', k, args_opts[k])

        profile = io.BytesIO()
        newconf.write(profile)

        t = Template(profile.getvalue())
        text = t.substitute({'NAME': name, 'ADDRESS': addr, 'PORT': port,
                             'TESTDIR': self.testdir,
                             'ROOTDIR': self.rootdir,
                             'TEST_USER': self.testuser})

        filename = os.path.join(self.testdir, '%s_profile.cfg' % name)
        with open(filename, 'wb') as f:
            f.write(text)

        return filename

    def setup_http(self, name, addr, port):
        httpdir = os.path.join(self.testdir, name)
        os.mkdir(httpdir)
        os.mkdir(os.path.join(httpdir, 'conf.d'))
        os.mkdir(os.path.join(httpdir, 'html'))
        os.mkdir(os.path.join(httpdir, 'logs'))
        os.symlink('/etc/httpd/modules', os.path.join(httpdir, 'modules'))

        with open(os.path.join(self.rootdir, 'tests/httpd.conf')) as f:
            t = Template(f.read())
            text = t.substitute({'HTTPROOT': httpdir,
                                 'HTTPADDR': addr,
                                 'HTTPPORT': port})
        filename = os.path.join(httpdir, 'httpd.conf')
        with open(filename, 'w+') as f:
            f.write(text)

        return filename

    def setup_idp_server(self, profile, name, addr, port, env):
        http_conf_file = self.setup_http(name, addr, port)
        cmd = [os.path.join(self.rootdir,
                            'ipsilon/install/ipsilon-server-install'),
               '--config-profile=%s' % profile]
        subprocess.check_call(cmd, env=env)
        os.symlink(os.path.join(self.rootdir, 'ipsilon'),
                   os.path.join(self.testdir, 'lib', name, 'ipsilon'))

        return http_conf_file

    def setup_sp_server(self, profile, name, addr, port, env):
        http_conf_file = self.setup_http(name, addr, port)
        cmd = [os.path.join(self.rootdir,
                            'ipsilon/install/ipsilon-client-install'),
               '--config-profile=%s' % profile]
        subprocess.check_call(cmd, env=env)

        return http_conf_file

    def setup_pgdb(self, datadir, env):
        cmd = ['/usr/bin/pg_ctl', 'initdb', '-D', datadir]
        subprocess.check_call(cmd, env=env)
        auth = 'host all all 127.0.0.1/24 trust\n'
        filename = os.path.join(datadir, 'pg_hba.conf')
        with open(filename, 'a') as f:
            f.write(auth)

    def start_http_server(self, conf, env):
        p = subprocess.Popen(['/usr/sbin/httpd', '-DFOREGROUND', '-f', conf],
                             env=env, preexec_fn=os.setsid)
        self.processes.append(p)

    def start_pgdb_server(self, datadir, rundir, log, addr, port, env):
        p = subprocess.Popen(['/usr/bin/pg_ctl', 'start', '-D', datadir, '-o',
                              '-c unix_socket_directories=%s -c port=%s -c \
                               listen_addresses=%s' % (rundir, port, addr),
                              '-l', log, '-w'],
                             env=env, preexec_fn=os.setsid)
        self.processes.append(p)
        p.wait()
        for d in ['adminconfig', 'userprefs', 'transactions', 'sessions']:
            cmd = ['/usr/bin/createdb', '-h', addr, '-p', port, d]
            subprocess.check_call(cmd, env=env)

    def wait(self):
        for p in self.processes:
            os.killpg(p.pid, signal.SIGTERM)

    def setup_servers(self, env=None):
        raise NotImplementedError()

    def run(self, env):
        exe = self.execname
        if exe.endswith('c'):
            exe = exe[:-1]
        return subprocess.call([exe], env=env)
