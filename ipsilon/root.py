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

from ipsilon.util.page import Page
from ipsilon.util import errors
from ipsilon.login.common import Login
from ipsilon.login.common import Logout
from ipsilon.admin.common import Admin
from ipsilon.providers.common import LoadProviders
from ipsilon.admin.info import InfoPlugins
from ipsilon.admin.login import LoginPlugins
from ipsilon.admin.providers import ProviderPlugins
import cherrypy

sites = dict()


class Root(Page):

    def __init__(self, site, template_env):
        if site not in sites:
            sites[site] = dict()
        if template_env:
            sites[site]['template_env'] = template_env
        super(Root, self).__init__(sites[site])

        # set up error pages
        cherrypy.config['error_page.400'] = errors.Error_400(self._site)
        cherrypy.config['error_page.401'] = errors.Error_401(self._site)
        cherrypy.config['error_page.500'] = errors.Errors(self._site)

        # now set up the default login plugins
        self.login = Login(self._site)
        self.logout = Logout(self._site)

        # set up idp providers now
        LoadProviders(self, self._site)

        # after all plugins are setup we can instantiate the admin pages
        self.admin = Admin(self._site, 'admin')
        InfoPlugins(self._site, self.admin)
        LoginPlugins(self._site, self.admin)
        ProviderPlugins(self._site, self.admin)

    def root(self):
        return self._template('index.html', title='Ipsilon')
