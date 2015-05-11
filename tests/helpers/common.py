#!/usr/bin/python
#
# Copyright (C) 2014 Ipsilon project Contributors, for license see COPYING

import ConfigParser
import io
import os
import pwd
import shutil
import signal
import random
from string import Template
import subprocess


WRAP_HOSTNAME = 'idp.ipsilon.dev'
TESTREALM = 'IPSILON.DEV'
TESTDOMAIN = 'ipsilon.dev'
KDC_DBNAME = 'db.file'
KDC_STASH = 'stash.file'
KDC_PASSWORD = 'ipsilon'
KRB5_CONF_TEMPLATE = '''
[libdefaults]
  default_realm = ${TESTREALM}
  dns_lookup_realm = false
  dns_lookup_kdc = false
  rdns = false
  ticket_lifetime = 24h
  forwardable = yes
  default_ccache_name = FILE://${TESTDIR}/ccaches/krb5_ccache_XXXXXX
  udp_preference_limit = 0

[realms]
  ${TESTREALM} = {
    kdc =${WRAP_HOSTNAME}
  }

[domain_realm]
  .${TESTDOMAIN} = ${TESTREALM}
  ${TESTDOMAIN} = ${TESTREALM}

[dbmodules]
  ${TESTREALM} = {
    database_name = ${KDCDIR}/${KDC_DBNAME}
  }
'''

KDC_CONF_TEMPLATE = '''
[kdcdefaults]
 kdc_ports = 88
 kdc_tcp_ports = 88
 restrict_anonymous_to_tgt = true

[realms]
 ${TESTREALM} = {
  master_key_type = aes256-cts
  max_life = 7d
  max_renewable_life = 14d
  acl_file = ${KDCDIR}/kadm5.acl
  dict_file = /usr/share/dict/words
  default_principal_flags = +preauth
  admin_keytab = ${TESTREALM}/kadm5.keytab
  key_stash_file = ${KDCDIR}/${KDC_STASH}
 }
[logging]
  kdc = FILE:${KDCLOG}
'''

USER_KTNAME = "user.keytab"
HTTP_KTNAME = "http.keytab"
KEY_TYPE = "aes256-cts-hmac-sha1-96:normal"


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

    def generate_profile(self, global_opts, args_opts, name, addr, port,
                         nameid='unspecified'):
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
                             'NAMEID': nameid,
                             'HTTP_KTNAME': HTTP_KTNAME,
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
        env['MALLOC_CHECK_'] = '3'
        env['MALLOC_PERTURB_'] = str(random.randint(0, 32767) % 255 + 1)
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
        for d in ['adminconfig', 'users', 'transactions', 'sessions',
                  'saml2.sessions.db']:
            cmd = ['/usr/bin/createdb', '-h', addr, '-p', port, d]
            subprocess.check_call(cmd, env=env)

    def setup_ldap(self, env):
        ldapdir = os.path.join(self.testdir, 'ldap')
        os.mkdir(ldapdir)
        with open(os.path.join(self.rootdir, 'tests/slapd.conf')) as f:
            t = Template(f.read())
            text = t.substitute({'ldapdir': ldapdir})
        filename = os.path.join(ldapdir, 'slapd.conf')
        with open(filename, 'w+') as f:
            f.write(text)
        subprocess.check_call(['/usr/sbin/slapadd', '-f', filename, '-l',
                               'tests/ldapdata.ldif'], env=env)

        return filename

    def start_ldap_server(self, conf, addr, port, env):
        p = subprocess.Popen(['/usr/sbin/slapd', '-d', '0', '-f', conf,
                             '-h', 'ldap://%s:%s' % (addr, port)],
                             env=env, preexec_fn=os.setsid)
        self.processes.append(p)

    def setup_kdc(self, env):

        # setup kerberos environment
        testlog = os.path.join(self.testdir, 'kerb.log')
        krb5conf = os.path.join(self.testdir, 'krb5.conf')
        kdcconf = os.path.join(self.testdir, 'kdc.conf')
        kdcdir = os.path.join(self.testdir, 'kdc')
        if os.path.exists(kdcdir):
            shutil.rmtree(kdcdir)
        os.makedirs(kdcdir)

        t = Template(KRB5_CONF_TEMPLATE)
        text = t.substitute({'TESTREALM': TESTREALM,
                             'TESTDOMAIN': TESTDOMAIN,
                             'TESTDIR': self.testdir,
                             'KDCDIR': kdcdir,
                             'KDC_DBNAME': KDC_DBNAME,
                             'WRAP_HOSTNAME': WRAP_HOSTNAME})
        with open(krb5conf, 'w+') as f:
            f.write(text)

        t = Template(KDC_CONF_TEMPLATE)
        text = t.substitute({'TESTREALM': TESTREALM,
                             'KDCDIR': kdcdir,
                             'KDCLOG': testlog,
                             'KDC_STASH': KDC_STASH})
        with open(kdcconf, 'w+') as f:
            f.write(text)

        kdcenv = {'PATH': '/sbin:/bin:/usr/sbin:/usr/bin',
                  'KRB5_CONFIG': krb5conf,
                  'KRB5_KDC_PROFILE': kdcconf}
        kdcenv.update(env)

        with (open(testlog, 'a')) as logfile:
            ksetup = subprocess.Popen(["kdb5_util", "create", "-s",
                                       "-r", TESTREALM, "-P", KDC_PASSWORD],
                                      stdout=logfile, stderr=logfile,
                                      env=kdcenv, preexec_fn=os.setsid)
        ksetup.wait()
        if ksetup.returncode != 0:
            raise ValueError('KDC Setup failed')

        kdcproc = subprocess.Popen(['krb5kdc', '-n'],
                                   env=kdcenv, preexec_fn=os.setsid)
        self.processes.append(kdcproc)

        return kdcenv

    def kadmin_local(self, cmd, env, logfile):
        ksetup = subprocess.Popen(["kadmin.local", "-q", cmd],
                                  stdout=logfile, stderr=logfile,
                                  env=env, preexec_fn=os.setsid)
        ksetup.wait()
        if ksetup.returncode != 0:
            raise ValueError('Kadmin local [%s] failed' % cmd)

    def setup_keys(self, env):

        testlog = os.path.join(self.testdir, 'kerb.log')

        svc_name = "HTTP/%s" % WRAP_HOSTNAME
        svc_keytab = os.path.join(self.testdir, HTTP_KTNAME)
        cmd = "addprinc -randkey -e %s %s" % (KEY_TYPE, svc_name)
        with (open(testlog, 'a')) as logfile:
            self.kadmin_local(cmd, env, logfile)
        cmd = "ktadd -k %s -e %s %s" % (svc_keytab, KEY_TYPE, svc_name)
        with (open(testlog, 'a')) as logfile:
            self.kadmin_local(cmd, env, logfile)

        usr_keytab = os.path.join(self.testdir, USER_KTNAME)
        cmd = "addprinc -randkey -e %s %s" % (KEY_TYPE, self.testuser)
        with (open(testlog, 'a')) as logfile:
            self.kadmin_local(cmd, env, logfile)
        cmd = "ktadd -k %s -e %s %s" % (usr_keytab, KEY_TYPE, self.testuser)
        with (open(testlog, 'a')) as logfile:
            self.kadmin_local(cmd, env, logfile)

        keys_env = {"KRB5_KTNAME": svc_keytab}
        keys_env.update(env)

        return keys_env

    def kinit_keytab(self, kdcenv):
        testlog = os.path.join(self.testdir, 'kinit.log')
        usr_keytab = os.path.join(self.testdir, USER_KTNAME)
        kdcenv['KRB5CCNAME'] = 'FILE:' + os.path.join(
            self.testdir, 'ccaches/user')
        with (open(testlog, 'a')) as logfile:
            logfile.write("\n%s\n" % kdcenv)
            ksetup = subprocess.Popen(["kinit", "-kt", usr_keytab,
                                       self.testuser],
                                      stdout=logfile, stderr=logfile,
                                      env=kdcenv, preexec_fn=os.setsid)
            ksetup.wait()
            if ksetup.returncode != 0:
                raise ValueError('kinit %s failed' % self.testuser)

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
