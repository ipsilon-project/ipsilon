# Copyright (C) 2016 Ipsilon project Contributors, for license see COPYING

from ipsilon.util.plugin import PluginObject, PluginInstaller, PluginLoader
from ipsilon.util.config import ConfigHelper
from ipsilon.util.log import Log


class AuthzProviderBase(ConfigHelper, PluginObject):
    def __init__(self, *pargs):
        ConfigHelper.__init__(self)
        PluginObject.__init__(self, *pargs)

    def authorize_user(self, provplugname, provinfo, user, attributes):
        raise NotImplementedError


FACILITY = 'authz_config'


class Authz(Log):
    def __init__(self, site):
        self._site = site

        plugins = PluginLoader(Authz, FACILITY, 'AuthzProvider')
        plugins.get_plugin_data()
        self._site[FACILITY] = plugins

        available = plugins.available.keys()
        self.debug('Available authorization providers: %s' % str(available))

        for item in plugins.enabled:
            self.debug('Authorization plugin in enabled list: %s' % item)
            if item not in plugins.available:
                self.debug('Authorization plugin %s not found' % item)
                continue
            try:
                plugins.available[item].enable()
            except Exception as e:  # pylint: disable=broad-except
                while item in plugins.enabled:
                    plugins.enabled.remove(item)
                self.debug("Authorization plugin %s couldn't be enabled: %s" %
                           (item, str(e)))

    def authorize_user(self, provplugname, provinfo, user, attributes):
        plugins = self._site[FACILITY]

        authorized = None

        for name in plugins.enabled:
            p = plugins.available[name]
            self.debug('Calling authorization provider %s' % p.name)
            result = p.authorize_user(provplugname, provinfo, user,
                                      attributes)
            self.debug('Authorization provider %s returned %s' % (p.name,
                                                                  str(result)))
            if result is not None:
                authorized = result
                break

        if authorized is None:
            self.debug('All authorization providers declined to authorize, '
                       'denying the request')
            authorized = False

        return authorized


class AuthzProviderInstaller(object):
    def __init__(self):
        self.facility = FACILITY
        self.ptype = 'authz'
        self.name = None

    def unconfigure(self, opts, changes):
        return

    def install_args(self, group):
        raise NotImplementedError

    def validate_args(self, args):
        return

    def configure(self, opts, changes):
        raise NotImplementedError


class AuthzProviderInstall(object):

    def __init__(self):
        pi = PluginInstaller(AuthzProviderInstall, FACILITY)
        self.plugins = pi.get_plugins()
