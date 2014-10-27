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

from ipsilon.util.log import Log
from ipsilon.util.plugin import PluginInstaller, PluginLoader
from ipsilon.util.plugin import PluginObject, PluginConfig
from ipsilon.util.page import Page
import cherrypy


class ProviderException(Exception, Log):

    def __init__(self, message):
        super(ProviderException, self).__init__(message)
        self.message = message

    def __str__(self):
        return repr(self.message)


class AuthenticationError(ProviderException):

    def __init__(self, message, code):
        super(AuthenticationError, self).__init__(message)
        self.code = code
        self._debug('%s [%s]' % (message, code))


class InvalidRequest(ProviderException):

    def __init__(self, message):
        super(InvalidRequest, self).__init__(message)
        self._debug(message)


class ProviderBase(PluginConfig, PluginObject):

    def __init__(self, name, path, *pargs):
        PluginConfig.__init__(self)
        PluginObject.__init__(self, *pargs)
        self.name = name
        self._root = None
        self.path = path
        self.tree = None

    def get_tree(self, site):
        raise NotImplementedError

    def register(self, root, site):

        self._root = root
        # init pages and admin interfaces
        self.tree = self.get_tree(site)
        self._debug('IdP Provider registered: %s' % self.name)

    def on_enable(self):
        self._root.add_subtree(self.name, self.tree)

    def on_disable(self):
        self._root.del_subtree(self.name)


class ProviderPageBase(Page):

    def __init__(self, site, config):
        super(ProviderPageBase, self).__init__(site)
        self.plugin_name = config.name
        self.cfg = config

    def GET(self, *args, **kwargs):
        raise cherrypy.HTTPError(501)

    def POST(self, *args, **kwargs):
        raise cherrypy.HTTPError(501)

    def root(self, *args, **kwargs):
        method = cherrypy.request.method

        preop = getattr(self, 'pre_%s' % method, None)
        if preop and callable(preop):
            preop(*args, **kwargs)

        op = getattr(self, method, self.GET)
        if callable(op):
            return op(*args, **kwargs)
        else:
            raise cherrypy.HTTPError(405)

    def _debug(self, fact):
        superfact = '%s: %s' % (self.plugin_name, fact)
        super(ProviderPageBase, self)._debug(superfact)

    def _audit(self, fact):
        cherrypy.log('%s: %s' % (self.plugin_name, fact))


FACILITY = 'provider_config'


class LoadProviders(Log):

    def __init__(self, root, site):
        plugins = PluginLoader(LoadProviders, FACILITY, 'IdpProvider')
        plugins.get_plugin_data()
        site[FACILITY] = plugins

        available = plugins.available.keys()
        self._debug('Available providers: %s' % str(available))

        for item in plugins.available:
            plugin = plugins.available[item]
            plugin.register(root, site)

        for item in plugins.enabled:
            self._debug('Provider plugin in enabled list: %s' % item)
            if item not in plugins.available:
                continue
            plugins.available[item].enable()


class ProvidersInstall(object):

    def __init__(self):
        pi = PluginInstaller(ProvidersInstall, FACILITY)
        self.plugins = pi.get_plugins()
