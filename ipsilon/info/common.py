#!/usr/bin/python
#
# Copyright (C) 2014 Ipsilon Project Contributors
#
# See the file named COPYING for the project license

from ipsilon.util.log import Log
from ipsilon.util.plugin import PluginLoader, PluginObject
from ipsilon.util.plugin import PluginInstaller


class InfoProviderBase(PluginObject):

    def __init__(self):
        super(InfoProviderBase, self).__init__()

    def get_user_attrs(self, user):
        raise NotImplementedError


FACILITY = 'info_config'


class Info(Log):

    def __init__(self, *args, **kwargs):
        self.providers = []

        loader = PluginLoader(Info, FACILITY, 'InfoProvider')
        plugins = loader.get_plugin_data()

        available = plugins['available'].keys()
        self.debug('Available info providers: %s' % str(available))

        for item in plugins['whitelist']:
            self.debug('Login plugin in whitelist: %s' % item)
            if item not in plugins['available']:
                self.debug('Info Plugin %s not found' % item)
                continue
            self.providers.append((item, plugins['available'][item]))
            self.debug('Added Info plugin: %s' % item)

    def get_user_attrs(self, user, provider=None):
        if provider:
            for p in self.providers:
                if p[0] == provider:
                    return p[1].get_user_attrs(user)
        else:
            for p in self.providers:
                ret = p[1].get_user_attrs(user)
                if ret:
                    return ret

        return None


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
