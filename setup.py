#!/usr/bin/python
#
# Copyright (C) 2014 Ipsilon project Contributors, for license see COPYING

from distutils.core import setup
from glob import glob

DATA = 'share/ipsilon/'

setup(
    name = 'ipsilon',
    version = '1.0.0',
    license = 'GPLv3+',
    maintainer = 'Ipsilon project Contributors',
    maintainer_email = 'ipsilon@lists.fedorahosted.org',
    url='https://fedorahosted.org/ipsilon/',
    packages = ['ipsilon', 'ipsilon.admin', 'ipsilon.rest',
                'ipsilon.login', 'ipsilon.info', 'ipsilon.util',
                'ipsilon.providers', 'ipsilon.providers.saml2',
                'ipsilon.providers.openid',
                'ipsilon.providers.openid.extensions',
                'ipsilon.providers.persona',
                'ipsilon.tools', 'ipsilon.helpers',
                'tests', 'tests.helpers'],
    data_files = [('share/man/man7', ['man/ipsilon.7']),
                  ('share/man/man5', ['man/ipsilon.conf.5']),
                  ('share/man/man1', ['man/ipsilon-client-install.1',
                                      'man/ipsilon-server-install.1']),
                  ('share/doc/ipsilon', ['COPYING', 'README']),
                  ('share/doc/ipsilon/examples', ['examples/ipsilon.conf',
                                                  'examples/apache.conf']),
                  (DATA+'ui/css', glob('ui/css/*.css')),
                  (DATA+'ui/img', glob('ui/img/*')),
                  (DATA+'ui/js', glob('ui/js/*.js')),
                  (DATA+'ui/saml2sp', glob('ui/saml2sp/*.html')),
                  (DATA+'templates', glob('templates/*.html')),
                  (DATA+'templates/admin', glob('templates/admin/*.html')),
                  (DATA+'templates/admin', glob('templates/admin/*.svg')),
                  (DATA+'templates/login', glob('templates/login/*.html')),
                  (DATA+'templates/saml2', glob('templates/saml2/*.html')),
                  (DATA+'templates/openid', glob('templates/openid/*')),
                  (DATA+'templates/persona', glob('templates/persona/*.html')),
                  (DATA+'templates/install', glob('templates/install/*.conf')),
                  (DATA+'templates/install/saml2',
                   glob('templates/install/saml2/*.conf')),
                  (DATA+'templates/admin/providers',
                   glob('templates/admin/providers/*.html')),
                 ],
    scripts = ['ipsilon/ipsilon',
               'ipsilon/install/ipsilon-server-install',
               'ipsilon/install/ipsilon-client-install']
)

