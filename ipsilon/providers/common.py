# Copyright (C) 2014 Ipsilon project Contributors, for license see COPYING

from ipsilon.util.log import Log
from ipsilon.util.plugin import PluginInstaller, PluginLoader
from ipsilon.util.plugin import PluginObject
from ipsilon.util.config import ConfigHelper
from ipsilon.util.page import Page
from ipsilon.util.page import admin_protect
from ipsilon.rest.common import RestPage
import cherrypy


class ProviderException(cherrypy.HTTPError, Log):
    statuscode = 500
    message = None

    def __init__(self, message, code=None):
        super(ProviderException, self).__init__(self.statuscode,
                                                message or self.message)
        self.message = message
        self.code = code
        self.debug('%s [%s]' % (self.message, self.code))

    def __str__(self):
        return repr(self.message)


class AuthenticationError(ProviderException):
    statuscode = 403

    def __init__(self, message, code=None):
        super(AuthenticationError, self).__init__(message, code)


class InvalidRequest(ProviderException):
    statuscode = 400

    def __init__(self, message, code=None):
        super(InvalidRequest, self).__init__(message, code)


class UnauthorizedRequest(ProviderException):
    statuscode = 401

    def __init__(self, message, code=None):
        super(UnauthorizedRequest, self).__init__(message, code)


class ProviderBase(ConfigHelper, PluginObject):

    def __init__(self, name, displayname, path, *pargs):
        ConfigHelper.__init__(self)
        PluginObject.__init__(self, *pargs)
        self.name = name
        self.displayname = displayname
        self._root = None
        self.path = path
        self.tree = None

    def get_tree(self, site):
        raise NotImplementedError

    def register(self, root, site):

        self._root = root
        # init pages and admin interfaces
        self.tree = self.get_tree(site)
        self.debug('IdP Provider registered: %s' % self.name)

    def on_enable(self):
        self._root.add_subtree(self.name, self.tree)

    def on_disable(self):
        self._root.del_subtree(self.name)

    def get_providers(self):
        return []

    def get_display_name(self):
        return self.displayname

    def get_client_display_name(self, clientid):
        raise NotImplementedError

    def consent_to_display(self, consentdata):
        raise NotImplementedError


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

    def debug(self, fact):
        superfact = '%s: %s' % (self.plugin_name, fact)
        super(ProviderPageBase, self).debug(superfact)

    def _audit(self, fact):
        cherrypy.log('%s: %s' % (self.plugin_name, fact))


FACILITY = 'provider_config'


class ProviderInstaller(object):
    def __init__(self):
        self.facility = FACILITY
        self.ptype = 'provider'
        self.name = None

    def unconfigure(self, opts, changes):
        return

    def install_args(self, group):
        raise NotImplementedError

    def validate_args(self, args):
        return

    def configure(self, opts, changes):
        raise NotImplementedError


class LoadProviders(Log):

    def __init__(self, root, site):
        plugins = PluginLoader(LoadProviders, FACILITY, 'IdpProvider')
        plugins.get_plugin_data()
        site[FACILITY] = plugins

        available = plugins.available.keys()
        self.debug('Available providers: %s' % str(available))

        for item in plugins.available:
            plugin = plugins.available[item]
            plugin.register(root, site)

        for item in plugins.enabled:
            self.debug('Provider plugin in enabled list: %s' % item)
            if item not in plugins.available:
                continue
            plugins.available[item].enable()


class ProvidersInstall(object):

    def __init__(self):
        pi = PluginInstaller(ProvidersInstall, FACILITY)
        self.plugins = pi.get_plugins()


class RestProviderBase(RestPage):

    def __init__(self, site, config):
        super(RestProviderBase, self).__init__(site)
        self.plugin_name = config.name
        self.cfg = config

    @admin_protect
    def GET(self, *args, **kwargs):
        raise cherrypy.HTTPError(501)

    @admin_protect
    def POST(self, *args, **kwargs):
        raise cherrypy.HTTPError(501)

    @admin_protect
    def DELETE(self, *args, **kwargs):
        raise cherrypy.HTTPError(501)

    @admin_protect
    def PUT(self, *args, **kwargs):
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

    def debug(self, fact):
        superfact = '%s: %s' % (self.plugin_name, fact)
        super(RestProviderBase, self).debug(superfact)

    def _audit(self, fact):
        cherrypy.log('%s: %s' % (self.plugin_name, fact))
