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
    version = '0.1',
    license = 'GPLv3+',
    packages = ['ipsilon', 'ipsilon.admin', 'ipsilon.login', 'ipsilon.util',
                'ipsilon.providers', 'ipsilon.providers.saml2'],
    data_files = [('share/man/man7', ["man/ipsilon.7"]),
                  ('share/doc/ipsilon', ['COPYING']),
                  ('share/doc/ipsilon/examples', ['examples/ipsilon.conf',
                                                  'examples/apache.conf']),
                  (DATA+'ui/css', glob('ui/css/*.css')),
                  (DATA+'ui/img', glob('ui/img/*')),
                  (DATA+'ui/js', glob('ui/js/*.js')),
                  (DATA+'templates', glob('templates/*.html')),
                  (DATA+'templates/admin', glob('templates/admin/*.html')),
                  (DATA+'templates/login', glob('templates/login/*.html')),
                  (DATA+'templates/saml2', glob('templates/saml2/*.html')),
                  (DATA+'templates/install', glob('templates/install/*.conf')),
                  (DATA+'templates/admin/providers',
                   glob('templates/admin/providers/*.html')),
                 ],
    scripts = ['ipsilon/ipsilon', 'ipsilon/install/ipsilon-server-install']
)

