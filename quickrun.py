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
import os
import subprocess
from string import Template


logger = None


def parse_args():
    parser = argparse.ArgumentParser(description=\
        'Run a test Ipsilon instance from the checkout directory')
    parser.add_argument('--workdir', default=os.path.join(os.getcwd(), 'qrun'),
                        help="Directory in which db/session files are stored")
    return vars(parser.parse_args())


CONF_TEMPLATE='''
[global]
debug = True

log.screen = True
base.mount = "/idp"
base.dir = "${BASEDIR}"
admin.config.db = "${ADMINDB}"
user.prefs.db = "${USERSDB}"
transactions.db = "${TRANSDB}"

tools.sessions.on = True
tools.sessions.storage_type = "file"
tools.sessions.storage_path = "${WORKDIR}/sessions"
tools.sessions.timeout = 60
tools.sessions.secure = False
tools.sessions.httponly = False
'''

ADMIN_TEMPLATE='''
CREATE TABLE login_config (name TEXT,option TEXT,value TEXT);
INSERT INTO login_config VALUES('global', 'order', 'testauth');
'''

USERS_TEMPLATE='''
CREATE TABLE users(name TEXT, option TEXT, value TEXT);
INSERT INTO users VALUES('admin', 'is_admin', '1');
'''

def config(workdir):
    os.makedirs(workdir)
    os.makedirs(os.path.join(workdir, 'sessions'))

    admin_db = os.path.join(workdir, 'adminconfig.sqlite')
    sql = os.path.join(workdir, 'admin.sql')
    with open(sql, 'w+') as f:
        f.write(ADMIN_TEMPLATE)
    subprocess.call(['sqlite3', '-init', sql, admin_db, '.quit'])

    users_db = os.path.join(workdir, 'users.sqlite')
    sql = os.path.join(workdir, 'users.sql')
    with open(sql, 'w+') as f:
        f.write(USERS_TEMPLATE)
    subprocess.call(['sqlite3', '-init', sql, users_db, '.quit'])

    trans_db = os.path.join(workdir, 'transactions.sqlite')

    t = Template(CONF_TEMPLATE)
    text = t.substitute({'BASEDIR': os.getcwd(),
                         'WORKDIR': workdir,
                         'ADMINDB': admin_db,
                         'USERSDB': users_db,
                         'TRANSDB': trans_db})
    conf = os.path.join(workdir, 'ipsilon.conf')
    with open(conf, 'w+') as f:
        f.write(text)
    return conf

if __name__ == '__main__':

    args = parse_args()

    penv = dict()
    penv.update(os.environ)
    penv['PYTHONPATH'] = './'

    if not os.path.exists(args['workdir']):
        conf = config(args['workdir'])
    else:
        conf = os.path.join(args['workdir'], 'ipsilon.conf')

    p = subprocess.Popen(['./ipsilon/ipsilon', conf], env=penv)
    p.wait()
