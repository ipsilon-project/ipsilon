#!/usr/bin/python
#
# Copyright (C) 2014 Ipsilon project Contributors, for license see COPYING

import argparse
import os
import shutil
import subprocess
from string import Template


logger = None


def parse_args():
    parser = argparse.ArgumentParser(description=\
        'Run a test Ipsilon instance from the checkout directory')
    parser.add_argument('--workdir', default=os.path.join(os.getcwd(), 'qrun'),
                        help="Directory in which db/session files are stored")
    parser.add_argument('--cleanup', '-c', action='store_true', default=False,
                        help="Wipe workdir before starting")
    return vars(parser.parse_args())


CONF_TEMPLATE="templates/install/ipsilon.conf"

ADMIN_TEMPLATE='''
CREATE TABLE login_config (name TEXT,option TEXT,value TEXT);
INSERT INTO login_config VALUES('global', 'enabled', 'testauth');
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

    users_db = os.path.join(workdir, 'userprefs.sqlite')
    sql = os.path.join(workdir, 'users.sql')
    with open(sql, 'w+') as f:
        f.write(USERS_TEMPLATE)
    subprocess.call(['sqlite3', '-init', sql, users_db, '.quit'])

    trans_db = os.path.join(workdir, 'transactions.sqlite')

    with open(CONF_TEMPLATE) as f:
        conf_template = f.read()
    t = Template(conf_template)
    text = t.substitute({'debugging': 'True',
                         'instance': 'idp',
                         'staticdir': os.getcwd(),
                         'datadir': workdir,
                         'admindb': admin_db,
                         'usersdb': users_db,
                         'transdb': trans_db,
                         'sesstype': 'file',
                         'sessopt': 'path',
                         'sessval': os.path.join(workdir, 'sessions'),
                         'secure': 'False',
                        })
    conf = os.path.join(workdir, 'ipsilon.conf')
    with open(conf, 'w+') as f:
        f.write(text)
    return conf

if __name__ == '__main__':

    args = parse_args()

    penv = dict()
    penv.update(os.environ)
    penv['PYTHONPATH'] = os.getcwd()

    exe = os.path.join(os.getcwd(), 'ipsilon/ipsilon')

    if args['cleanup']:
        shutil.rmtree(args['workdir'])

    if not os.path.exists(args['workdir']):
        conf = config(args['workdir'])
    else:
        conf = os.path.join(args['workdir'], 'ipsilon.conf')

    if not os.path.exists(os.path.join(args['workdir'], 'ui')):
        os.symlink(os.path.join(os.getcwd(), 'ui'),
                   os.path.join(args['workdir'], 'ui'))


    os.chdir(args['workdir'])

    p = subprocess.Popen([exe, conf], env=penv)
    p.wait()
