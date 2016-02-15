#!/usr/bin/python
#
# Copyright (C) 2014 Ipsilon project Contributors, for license see COPYING

from helpers.common import IpsilonTestBase  # pylint: disable=relative-import
from helpers.http import HttpSessions  # pylint: disable=relative-import
import os
import pwd
import sys
import signal
import subprocess
import ipsilon.util.data

idp_g = {'TEMPLATES': '${TESTDIR}/templates/install',
         'CONFDIR': '${TESTDIR}/etc',
         'DATADIR': '${TESTDIR}/lib',
         'CACHEDIR': '${TESTDIR}/cache',
         'HTTPDCONFD': '${TESTDIR}/${NAME}/conf.d',
         'STATICDIR': '${ROOTDIR}',
         'BINDIR': '${ROOTDIR}/ipsilon',
         'WSGI_SOCKET_PREFIX': '${TESTDIR}/${NAME}/logs/wsgi'}


idp_a = {'hostname': '${ADDRESS}:${PORT}',
         'admin_user': '${TEST_USER}',
         'system_user': '${TEST_USER}',
         'instance': '${NAME}',
         'testauth': 'yes',
         'pam': 'no',
         'gssapi': 'no',
         'ipa': 'no',
         'server_debugging': 'True'}


class IpsilonTest(IpsilonTestBase):

    def __init__(self):
        super(IpsilonTest, self).__init__('dbupgrades', __file__)

    def setup_servers(self, env=None):
        pass

    def test_upgrade_from(self, env, old_version):
        # Setup IDP Server
        print "Installing IDP server to test upgrade from %i" % old_version
        name = 'idp_v%i' % old_version
        addr = '127.0.0.%i' % (10 + old_version)
        port = str(45080 + old_version)
        idp = self.generate_profile(idp_g, idp_a, name, addr, port)
        conf = self.setup_idp_server(idp, name, addr, port, env)

        # Move database of old_version into place
        cfgfile = os.path.join(self.testdir, 'etc', name, 'ipsilon.conf')
        db_indir = os.path.join(self.rootdir, 'tests', 'blobs', 'old_dbs',
                                'v%i' % old_version)
        db_outdir = os.path.join(self.testdir, 'lib', name)

        if old_version > 0:
            for database in ['adminconfig',
                             'openid',
                             'saml2.sessions.db',
                             'transactions',
                             'userprefs']:
                db_in = os.path.join(db_indir, '%s.sqlite.dump' % database)
                db_out = os.path.join(db_outdir, '%s.sqlite' % database)
                os.unlink(db_out)
                cmd = ['/usr/bin/sqlite3', db_out, '.read %s' % db_in]
                subprocess.check_call(cmd)

            # Upgrade that database
            cmd = [os.path.join(self.rootdir,
                                'ipsilon/install/ipsilon-upgrade-database'),
                   cfgfile]
            subprocess.check_call(cmd,
                                  cwd=os.path.join(self.testdir, 'lib', name),
                                  env=env)

        # Check some version-specific changes, to see if the upgrade went OK
        if old_version == 0:
            # Check all features in a newly created database
            # Let's verify if at least one index was created
            test_db = os.path.join(db_outdir, 'adminconfig.sqlite')
            p = subprocess.Popen(['/usr/bin/sqlite3', test_db, '.dump'],
                                 stdout=subprocess.PIPE)
            output, _ = p.communicate()
            if p.returncode:
                print 'Sqlite dump failed'
                sys.exit(1)
            if 'CREATE INDEX' not in output:
                raise Exception('Database upgrade did not introduce index')
            if 'PRIMARY KEY' not in output:
                raise Exception('Database upgrade did not introduce primary ' +
                                'key')
        elif old_version == 1:
            # In 1 -> 2, we added indexes and primary keys
            # Let's verify if at least one index was created
            test_db = os.path.join(db_outdir, 'adminconfig.sqlite')
            p = subprocess.Popen(['/usr/bin/sqlite3', test_db, '.dump'],
                                 stdout=subprocess.PIPE)
            output, _ = p.communicate()
            if p.returncode:
                print 'Sqlite dump failed'
                sys.exit(1)
            if 'CREATE INDEX' not in output:
                raise Exception('Database upgrade did not introduce index')
            # SQLite did not support creating primary keys, so we can't test

        # Start the httpd server
        http_server = self.start_http_server(conf, env)

        # Now attempt to use the upgraded database
        exe = self.execname
        if exe.endswith('c'):
            exe = exe[:-1]
        exe = [exe]
        exe.append(str(old_version))
        exe.append(name)
        exe.append('%s:%s' % (addr, port))
        exit_code = subprocess.call(exe, env=env)
        if exit_code:
            sys.exit(exit_code)

        # Now kill the last http server
        os.killpg(http_server.pid, signal.SIGTERM)
        self.processes.remove(http_server)

    def run(self, env):
        for version in range(ipsilon.util.data.CURRENT_SCHEMA_VERSION):
            self.test_upgrade_from(env, version)


if __name__ == '__main__':
    from_version = sys.argv[1]
    idpname = sys.argv[2]
    url = sys.argv[3]

    user = pwd.getpwuid(os.getuid())[0]

    sess = HttpSessions()
    sess.add_server(idpname, 'https://%s' % url, user,
                    'ipsilon')

    print "dbupgrades: From v%s: Authenticate to IDP ..." % from_version,
    try:
        sess.auth_to_idp(idpname)
    except Exception, e:  # pylint: disable=broad-except
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"
