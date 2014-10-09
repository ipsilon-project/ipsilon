#!/usr/bin/python
#
# Copyright (C) 2014 Ipsilon Project Contributors
#
# See the file named COPYING for the project license

from ipsilon.util.log import Log
from ipsilon.util.plugin import PluginLoader, PluginObject
from ipsilon.util.plugin import PluginInstaller


class InfoProviderBase(PluginObject, Log):

    def __init__(self):
        super(InfoProviderBase, self).__init__()
        self.enabled = False

    def get_user_attrs(self, user):
        raise NotImplementedError

    @property
    def is_enabled(self):
        return self.enabled

    def enable(self, site):
        self.enabled = True

        plugins = site[FACILITY]
        if self in plugins['enabled']:
            return

        # configure self
        if self.name in plugins['config']:
            self.set_config(plugins['config'][self.name])

        plugins['enabled'].append(self)
        self.debug('Info plugin enabled: %s' % self.name)

    def disable(self, site):
        self.enabled = False

        plugins = site[FACILITY]
        if self not in plugins['enabled']:
            return

        plugins['enabled'].remove(self)
        self.debug('Info plugin disabled: %s' % self.name)


FACILITY = 'info_config'


class Info(Log):

    def __init__(self, site):
        self._site = site

        loader = PluginLoader(Info, FACILITY, 'InfoProvider')
        self._site[FACILITY] = loader.get_plugin_data()
        plugins = self._site[FACILITY]

        available = plugins['available'].keys()
        self.debug('Available info providers: %s' % str(available))

        plugins['root'] = self
        for item in plugins['whitelist']:
            self.debug('Login plugin in whitelist: %s' % item)
            if item not in plugins['available']:
                self.debug('Info Plugin %s not found' % item)
                continue
            plugins['available'][item].enable(self._site)

    def get_user_attrs(self, user, requested=None):
        plugins = self._site[FACILITY]['available']
        result = dict()

        for _, p in plugins.items():
            if requested is None:
                if not p.is_enabled:
                    continue
            else:
                if requested != p.name:
                    continue
            result = p.get_user_attrs(user)
            if result:
                break

        return result


class InfoProviderInstaller(object):

    def __init__(self):
        self.facility = FACILITY
        self.ptype = 'info'
        self.name = None

    def install_args(self, group):
        raise NotImplementedError

    def configure(self, opts):
        raise NotImplementedError


class InfoProviderInstall(object):

    def __init__(self):
        pi = PluginInstaller(InfoProviderInstall)
        self.plugins = pi.get_plugins()
