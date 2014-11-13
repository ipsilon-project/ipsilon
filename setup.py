#!/usr/bin/python
#
# Copyright (C) 2013  Simo Sorce <simo@redhat.com>
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

from distutils.core import setup
from glob import glob

DATA = 'share/ipsilon/'

setup(
    name = 'ipsilon',
    version = '0.2.6',
    license = 'GPLv3+',
    maintainer = 'Simo Sorce',
    maintainer_email = 'simo@redhat.com',
    url='https://fedorahosted.org/ipsilon/',
    packages = ['ipsilon', 'ipsilon.admin', 'ipsilon.login',
                'ipsilon.info', 'ipsilon.util',
                'ipsilon.providers', 'ipsilon.providers.saml2',
                'ipsilon.providers.openid',
                'ipsilon.providers.openid.extensions',
                'ipsilon.providers.persona',
                'ipsilon.tools', 'ipsilon.helpers',
                'tests', 'tests.helpers'],
    data_files = [('share/man/man7', ["man/ipsilon.7"]),
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
                  (DATA+'templates/openid', glob('templates/openid/*.html')),
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

