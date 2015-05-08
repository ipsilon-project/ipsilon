# Copyright (C) 2013 Ipsilon project Contributors, for license see COPYING

from ipsilon.util.page import Page
from ipsilon.util import errors
from ipsilon.login.common import Login
from ipsilon.login.common import Logout
from ipsilon.admin.common import Admin
from ipsilon.providers.common import LoadProviders
from ipsilon.admin.loginstack import LoginStack
from ipsilon.admin.info import InfoPlugins
from ipsilon.admin.login import LoginPlugins
from ipsilon.admin.providers import ProviderPlugins
from ipsilon.rest.common import Rest
from ipsilon.rest.providers import RestProviderPlugins
import cherrypy

sites = dict()


class Root(Page):

    def __init__(self, site, template_env):
        if site not in sites:
            sites[site] = dict()
        if template_env:
            sites[site]['template_env'] = template_env
        super(Root, self).__init__(sites[site])
        self.html_heads = dict()

        # set up error pages
        cherrypy.config['error_page.400'] = errors.Error_400(self._site)
        cherrypy.config['error_page.401'] = errors.Error_401(self._site)
        cherrypy.config['error_page.404'] = errors.Error_404(self._site)
        cherrypy.config['error_page.500'] = errors.Errors(self._site)

        # now set up the default login plugins
        self.login = Login(self._site)
        self.logout = Logout(self._site)

        # set up idp providers now
        LoadProviders(self, self._site)

        # after all plugins are setup we can instantiate the admin pages
        self.admin = Admin(self._site, 'admin')
        self.rest = Rest(self._site, 'rest')
        self.stack = LoginStack(self._site, self.admin)
        LoginPlugins(self._site, self.stack)
        InfoPlugins(self._site, self.stack)
        ProviderPlugins(self._site, self.admin)
        RestProviderPlugins(self._site, self.rest)

    def root(self):
        self.debug(self.html_heads)
        return self._template('index.html', title='Ipsilon',
                              heads=self.html_heads)
