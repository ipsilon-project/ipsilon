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
from ipsilon.util.config import Config
from ipsilon.util.data import AdminStore
from ipsilon.util.log import Log


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
            # elif ext.lower() == '.pyc':
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
        config = AdminStore().load_options(facility)
        cherrypy.log('LOAD: %s\n' % repr(config))
        whitelist = []
        if 'global' in config:
            sec = config['global']
            if 'order' in sec:
                whitelist = sec['order'].split(',')
        if cherrypy.config.get('debug', False):
            cherrypy.log('[%s] %s: %s' % (facility, whitelist, config))
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


class PluginInstaller(object):
    def __init__(self, baseobj):
        (pathname, dummy) = os.path.split(inspect.getfile(baseobj))
        self._pathname = pathname

    def get_plugins(self):
        p = Plugins()
        return p.get_plugins(self._pathname, 'Installer')


class PluginObject(Log):

    def __init__(self):
        self.name = None
        self._config = None
        self._data = AdminStore()

    def import_config(self, config):
        self._config = config

    def export_config(self):
        return self._config

    def get_plugin_config(self, facility):
        return self._data.load_options(facility, self.name)

    def refresh_plugin_config(self, facility):
        config = self.get_plugin_config(facility)
        self.import_config(config)

    def save_plugin_config(self, facility, config=None):
        if config is None:
            config = self.export_config()

        self._data.save_options(facility, self.name, config)

    def get_data(self, idval=None, name=None, value=None):
        return self._data.get_data(self.name, idval=idval, name=name,
                                   value=value)

    def save_data(self, data):
        self._data.save_data(self.name, data)

    def new_datum(self, datum):
        self._data.new_datum(self.name, datum)

    def del_datum(self, idval):
        self._data.del_datum(self.name, idval)

    def wipe_config_values(self, facility):
        self._data.delete_options(facility, self.name, None)

    def wipe_data(self):
        self._data.wipe_data(self.name)


class PluginConfig(Log):

    def __init__(self):
        self._config = None

    def new_config(self, name, *config_args):
        self._config = Config(name, *config_args)

    def get_config_obj(self):
        if self._config is None:
            raise AttributeError('Config not initialized')
        return self._config

    def import_config(self, config):
        if not self._config:
            raise AttributeError('Config not initialized, cannot import')

        for key, value in config.iteritems():
            if key in self._config:
                self._config[key].import_value(str(value))

    def export_config(self):
        config = dict()
        for name, option in self._config.iteritems():
            config[name] = option.export_value()
        return config

    def get_config_value(self, name):
        if not self._config:
            raise AttributeError('Config not initialized')
        return self._config[name].get_value()

    def set_config_value(self, name, value):
        if not self._config:
            raise AttributeError('Config not initialized')
        return self._config[name].set_value(value)
