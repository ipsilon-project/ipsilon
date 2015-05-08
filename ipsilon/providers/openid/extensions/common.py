# Copyright (C) 2014 Ipsilon project Contributors, for license see COPYING

from __future__ import absolute_import

from ipsilon.providers.common import FACILITY
from ipsilon.util.plugin import PluginLoader
from ipsilon.util.log import Log


class OpenidExtensionBase(Log):

    def __init__(self, name=None):
        self.name = name
        self.enabled = False
        self.type_uris = []

    def _display(self, request, userdata):
        raise NotImplementedError

    def _response(self, request, userdata):
        raise NotImplementedError

    def get_type_uris(self):
        if self.enabled:
            return self.type_uris
        return []

    def get_display_data(self, request, userdata):
        if self.enabled:
            return self._display(request, userdata)
        return {}

    def get_response(self, request, userdata):
        if self.enabled:
            return self._response(request, userdata)
        return None

    def enable(self):
        self.enabled = True

    def disable(self):
        self.enabled = False


FACILITY = 'openid_extensions'


class LoadExtensions(Log):

    def __init__(self):
        self.plugins = PluginLoader(LoadExtensions,
                                    FACILITY, 'OpenidExtension')
        self.plugins.get_plugin_data()

        available = self.plugins.available.keys()
        self.debug('Available Extensions: %s' % str(available))

    def enable(self, enabled):
        for item in enabled:
            if item not in self.plugins.available:
                self.debug('<%s> not available' % item)
                continue
            self.debug('Enable OpenId extension: %s' % item)
            self.plugins.available[item].enable()

    def available(self):
        return self.plugins.available
