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

import os
import imp
import cherrypy
import inspect
from ipsilon.util.data import Store


class Plugins(object):

    def __init__(self):
        self._providers_tree = None

    def _load_class(self, tree, class_type, file_name):
        cherrypy.log.error('Check module %s for class %s' % (file_name,
                                                             class_type))
        name, ext = os.path.splitext(os.path.split(file_name)[-1])
        try:
            if ext.lower() == '.py':
                mod = imp.load_source(name, file_name)
            #elif ext.lower() == '.pyc':
            #    mod = imp.load_compiled(name, file_name)
            else:
                return
        except Exception, e:  # pylint: disable=broad-except
            cherrypy.log.error('Failed to load "%s" module: [%s]' % (name, e))
            return

        if hasattr(mod, class_type):
            instance = getattr(mod, class_type)()
            public_name = getattr(instance, 'name', name)
            tree[public_name] = instance
            cherrypy.log.error('Added module %s as %s' % (name, public_name))

    def _load_classes(self, tree, path, class_type):
        files = None
        try:
            files = os.listdir(path)
        except Exception, e:  # pylint: disable=broad-except
            cherrypy.log.error('No modules in %s: [%s]' % (path, e))
            return

        for name in files:
            filename = os.path.join(path, name)
            self._load_class(tree, class_type, filename)

    def get_plugins(self, path, class_type):
        plugins = dict()
        self._load_classes(plugins, path, class_type)
        return plugins


class PluginLoader(object):

    def __init__(self, baseobj, facility, plugin_type):
        (whitelist, config) = Store().get_plugins_config(facility)
        if cherrypy.config.get('debug', False):
            cherrypy.log('[%s] %s: %s' % (facility, whitelist, config))
        if whitelist is None:
            whitelist = []
        if config is None:
            config = dict()

        p = Plugins()
        (pathname, dummy) = os.path.split(inspect.getfile(baseobj))
        self._plugins = {
            'config': config,
            'available': p.get_plugins(pathname, plugin_type),
            'whitelist': whitelist,
            'enabled': []
        }

    def get_plugin_data(self):
        return self._plugins


class PluginObject(object):

    def __init__(self):
        self.name = None
        self._config = None
        self._options = None
        self._data = Store()

    def get_config_desc(self):
        """ The configuration description is a dictionary that provides
            A description of the supported configuration options, as well
            as the default configuration option values.
            The key is the option name, the value is an array of 3 elements:
             - description
             - option type
             - default value
        """
        return self._options

    def set_config(self, config):
        self._config = config

    def get_config_value(self, name):
        value = None
        if self._config:
            value = self._config.get(name, None)
        if not value:
            if self._options:
                opt = self._options.get(name, None)
                if opt:
                    value = opt[2]

        if cherrypy.config.get('debug', False):
            cherrypy.log('[%s] %s: %s' % (self.name, name, value))

        return value

    def set_config_value(self, option, value):
        if not self._config:
            self._config = dict()
        self._config[option] = value

    def get_data(self, idval=None, name=None, value=None):
        return self._data.get_data(self.name, idval=idval, name=name,
                                   value=value)

    def save_data(self, data):
        self._data.save_data(self.name, data)
