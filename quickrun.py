#!/usr/bin/python
#
# Copyright (C) 2014 Ipsilon project Contributors, for license see COPYING

import argparse
import os
import shutil
import subprocess
from string import Template
from datetime import timedelta

from ipsilon.tools.certs import Certificate
from ipsilon.providers.saml2idp import IdpMetadataGenerator

from jwcrypto.jwk import JWK, JWKSet


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
CREATE TABLE provider_config (name TEXT,option TEXT,value TEXT);
INSERT INTO provider_config VALUES('global', 'enabled', 'saml2,openidc');
INSERT INTO provider_config VALUES('saml2', 'idp storage path',
                                   '${workdir}/saml2');
INSERT INTO provider_config VALUES('openidc', 'idp key file',
                                   '${workdir}/openidc.key');
INSERT INTO provider_config VALUES('openidc', 'idp sig key id',
                                   'quickstart');
'''

USERS_TEMPLATE='''
CREATE TABLE users(name TEXT, option TEXT, value TEXT);
INSERT INTO users VALUES('admin', 'is_admin', '1');
'''

def config(workdir):
    os.makedirs(workdir)
    os.makedirs(os.path.join(workdir, 'sessions'))
    os.makedirs(os.path.join(workdir, 'saml2'))

    admin_db = os.path.join(workdir, 'adminconfig.sqlite')
    sql = os.path.join(workdir, 'admin.sql')
    t = Template(ADMIN_TEMPLATE)
    text = t.substitute({'workdir': workdir})
    with open(sql, 'w+') as f:
        f.write(text)
    subprocess.call(['/usr/bin/sqlite3', '-init', sql, admin_db, '.quit'])

    users_db = os.path.join(workdir, 'userprefs.sqlite')
    sql = os.path.join(workdir, 'users.sql')
    with open(sql, 'w+') as f:
        f.write(USERS_TEMPLATE)
    subprocess.call(['/usr/bin/sqlite3', '-init', sql, users_db, '.quit'])

    trans_db = os.path.join(workdir, 'transactions.sqlite')
    cachedir = os.path.join(workdir, 'cache')

    with open(CONF_TEMPLATE) as f:
        conf_template = f.read()
    t = Template(conf_template)
    text = t.substitute({'debugging': 'True',
                         'instance': 'idp',
                         'staticdir': os.getcwd(),
                         'datadir': workdir,
                         'cachedir': cachedir,
                         'admindb': admin_db,
                         'usersdb': users_db,
                         'transdb': trans_db,
                         'sesstype': 'file',
                         'sessopt': 'path',
                         'sessval': os.path.join(workdir, 'sessions'),
                         'secure': 'False',
                         'cleanup_interval': 1,
                        })
    conf = os.path.join(workdir, 'ipsilon.conf')
    with open(conf, 'w+') as f:
        f.write(text)
    return conf


def init(workdir):
    # Initialize SAML2, since this is quite tricky to get right
    cert = Certificate(os.path.join(workdir, 'saml2'))
    cert.generate('certificate', 'ipsilon-quickrun')
    url = 'http://localhost:8080/idp'
    validity = 365 * 5
    meta = IdpMetadataGenerator(url, cert,
                                timedelta(validity))
    meta.output(os.path.join(workdir, 'saml2', 'metadata.xml'))

    # Also initalize OpenID Connect
    keyfile = os.path.join(workdir, 'openidc.key')
    keyset = JWKSet()
    # We generate one RSA2048 signing key
    rsasig = JWK(generate='RSA', size=2048, use='sig', kid='quickstart')
    keyset.add(rsasig)
    with open(keyfile, 'w') as m:
	m.write(keyset.export())


if __name__ == '__main__':

    args = parse_args()

    penv = dict()
    penv.update(os.environ)
    penv['PYTHONPATH'] = os.getcwd()

    schema_init = os.path.join(os.getcwd(), 'ipsilon/install/ipsilon-upgrade-database')
    exe = os.path.join(os.getcwd(), 'ipsilon/ipsilon')

    if args['cleanup']:
        shutil.rmtree(args['workdir'])

    if not os.path.exists(args['workdir']):
        conf = config(args['workdir'])
        init(args['workdir'])
    else:
        conf = os.path.join(args['workdir'], 'ipsilon.conf')

    if not os.path.exists(os.path.join(args['workdir'], 'ui')):
        os.symlink(os.path.join(os.getcwd(), 'ui'),
                   os.path.join(args['workdir'], 'ui'))

    if not os.path.exists(os.path.join(args['workdir'], 'cache')):
        # This is only used in quickrun. Apache serves this directly
        os.makedirs(os.path.join(args['workdir'], 'cache'))

    os.chdir(args['workdir'])

    p = subprocess.Popen([schema_init, conf], env=penv)
    p.wait()

    if p.returncode == 0:
        p = subprocess.Popen([exe, conf], env=penv)
        p.wait()
