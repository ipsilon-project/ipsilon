# Copyright (C) 2016 Ipsilon project Contributors, for license see COPYING

from __future__ import absolute_import

from ipsilon.util.plugin import PluginLoader
from ipsilon.util.log import Log


class OpenidCExtensionBase(Log):

    def __init__(self, provider, name, display_name, scopes):
        self.name = name
        self.display_name = display_name
        # A mapping of scope to display string for supported scopes
        self.scopes = scopes
        self.enabled = False
        self.provider = None

    def get_scopes(self):
        if not self.enabled:
            return []

        return self.scopes.keys()

    def get_display_name(self):
        return self.display_name

    def get_display_data(self, scopes):
        if not self.enabled:
            return {}

        display_data = {}
        for scope in scopes:
            if scope in self.scopes:
                display_data[scope] = self.scopes[scope]
        return display_data

    def enable(self, provider):
        self.enabled = True
        self.provider = provider

    def disable(self):
        self.enabled = False
        self.provider = None


FACILITY = 'openidc_extensions'


class LoadExtensions(Log):

    def __init__(self):
        self.plugins = PluginLoader(LoadExtensions,
                                    FACILITY, 'OpenidCExtension', False)
        self.plugins.get_plugin_data()

        available = self.plugins.available.keys()
        self.debug('Available Extensions: %s' % str(available))

    def enable(self, enabled, provider):
        for item in enabled:
            if item not in self.plugins.available:
                self.debug('<%s> not available' % item)
                continue
            self.debug('Enable OpenId Connect extension: %s' % item)
            self.plugins.available[item].enable(provider)

    def available(self):
        return self.plugins.available
