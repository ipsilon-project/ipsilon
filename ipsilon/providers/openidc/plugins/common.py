# Copyright (C) 2016 Ipsilon project Contributors, for license see COPYING

from __future__ import absolute_import

from ipsilon.util.plugin import PluginLoader
from ipsilon.util.log import Log


class OpenidCExtensionBase(Log):
    name = None
    display_name = None
    # A mapping of scope to dict with scope info
    scopes = {}

    def __init__(self, provider):
        if self.name is None:
            raise NotImplementedError('Name missing for OpenIDC extensions')
        self.enabled = False
        self.provider = None

    def get_scopes(self):
        if not self.enabled:
            return []

        return self.scopes.keys()

    def get_display_name(self):
        if self.display_name:
            return self.display_name
        else:
            return self.name

    def get_display_data(self, scopes):
        if not self.enabled:
            return {}

        display_data = {}
        for scope in scopes:
            if scope in self.scopes:
                if 'display_name' in self.scopes[scope]:
                    display_data[scope] = self.scopes[scope]['display_name']
                else:
                    display_data[scope] = scope
        return display_data

    def get_claims(self, scopes):
        if not self.enabled:
            return {}

        claims = []
        for scope in scopes:
            if scope in self.scopes and 'claims' in self.scopes[scope]:
                data = self.scopes[scope]['claims']
                if not isinstance(data, list):
                    data = [data]
                claims.extend(data)
        return claims

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
