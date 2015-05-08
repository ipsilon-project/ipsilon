# Copyright (C) 2013 Ipsilon project Contributors, for license see COPYING

import os
import imp
import cherrypy
import inspect
import logging
from ipsilon.util.data import AdminStore
from ipsilon.util.log import Log


class Plugins(object):

    def __init__(self):
        self._providers_tree = None

    def _load_class(self, tree, class_type, file_name, *pargs):
        cherrypy.log.error('Check module %s for class %s' % (file_name,
                           class_type), severity=logging.DEBUG)
        name, ext = os.path.splitext(os.path.split(file_name)[-1])
        try:
            if ext.lower() == '.py':
                mod = imp.load_source(name, file_name)
            # elif ext.lower() == '.pyc':
            #    mod = imp.load_compiled(name, file_name)
            else:
                return
        except Exception, e:  # pylint: disable=broad-except
            cherrypy.log.error('Failed to load "%s" module: [%s]' % (name, e),
                               severity=logging.ERROR)
            return

        if hasattr(mod, class_type):
            instance = getattr(mod, class_type)(*pargs)
            public_name = getattr(instance, 'name', name)
            tree[public_name] = instance
            cherrypy.log.error('Added module %s as %s' % (name, public_name),
                               severity=logging.DEBUG)

    def _load_classes(self, tree, path, class_type, *pargs):
        files = None
        try:
            files = os.listdir(path)
        except Exception, e:  # pylint: disable=broad-except
            cherrypy.log.error('No modules in %s: [%s]' % (path, e),
                               severity=logging.ERROR)
            return

        for name in files:
            filename = os.path.join(path, name)
            self._load_class(tree, class_type, filename, *pargs)

    def get_plugins(self, path, class_type, *pargs):
        plugins = dict()
        self._load_classes(plugins, path, class_type, *pargs)
        return plugins


class PluginLoader(Log):

    def __init__(self, baseobj, facility, plugin_type):
        self._pathname, _ = os.path.split(inspect.getfile(baseobj))
        self.facility = facility
        self._plugin_type = plugin_type
        self.available = dict()
        self.enabled = list()
        self.__data = None

    # Defer initialization or instantiating the store will fail at load
    # time when used with Installer plugins as the cherrypy config context
    # is created after all Installer plugins are loaded.
    @property
    def _data(self):
        if not self.__data:
            self.__data = AdminStore()
        return self.__data

    @property
    def is_readonly(self):
        return self._data.is_readonly

    def get_plugins(self):
        p = Plugins()
        return p.get_plugins(self._pathname, self._plugin_type, self)

    def refresh_enabled(self):
        config = self._data.load_options(self.facility, name='global')
        self.enabled = []
        if config:
            if 'enabled' in config:
                self.enabled = config['enabled'].split(',')

    def get_plugin_data(self):
        self.available = self.get_plugins()
        self.refresh_enabled()

    def save_enabled(self, enabled):
        if enabled:
            self._data.save_options(self.facility, 'global',
                                    {'enabled': ','.join(enabled)})
        else:
            self._data.delete_options(self.facility, 'global',
                                      {'enabled': '*'})
        self.debug('Plugin enabled state saved: %s' % enabled)
        self.refresh_enabled()


class PluginInstaller(PluginLoader):
    def __init__(self, baseobj, facility):
        super(PluginInstaller, self).__init__(baseobj, facility, 'Installer')


class PluginObject(Log):

    def __init__(self, plugins):
        self.name = None
        self._config = None
        self._data = AdminStore()
        self._plugins = plugins
        self.is_enabled = False

    @property
    def is_readonly(self):
        return self._data.is_readonly

    def on_enable(self):
        return

    def on_disable(self):
        return

    def save_enabled_state(self):
        enabled = []
        self._plugins.refresh_enabled()
        enabled.extend(self._plugins.enabled)
        if self.is_enabled:
            if self.name not in enabled:
                enabled.append(self.name)
        else:
            if self.name in enabled:
                enabled.remove(self.name)
        self._plugins.save_enabled(enabled)

    def enable(self):
        if self.is_enabled:
            return

        self.refresh_plugin_config()
        self.on_enable()
        self.is_enabled = True
        self.debug('Plugin enabled: %s' % self.name)

    def disable(self):
        if not self.is_enabled:
            return

        self.on_disable()

        self.is_enabled = False
        self.debug('Plugin disabled: %s' % self.name)

    def import_config(self, config):
        self._config = config

    def export_config(self):
        return self._config

    def get_plugin_config(self):
        return self._data.load_options(self._plugins.facility, self.name)

    def refresh_plugin_config(self):
        config = self.get_plugin_config()
        if config:
            try:
                self.import_config(config)
            except Exception, e:  # pylint: disable=broad-except
                self.error('Failed to refresh config for %s (%s)' %
                           (self.name, e))

    def save_plugin_config(self, config=None):
        if config is None:
            config = self.export_config()

        self._data.save_options(self._plugins.facility, self.name, config)

    def get_data(self, idval=None, name=None, value=None):
        return self._data.get_data(self.name, idval=idval, name=name,
                                   value=value)

    def save_data(self, data):
        self._data.save_data(self.name, data)

    def new_datum(self, datum):
        self._data.new_datum(self.name, datum)

    def del_datum(self, idval):
        self._data.del_datum(self.name, idval)

    def wipe_config_values(self):
        self._data.delete_options(self._plugins.facility, self.name, None)

    def wipe_data(self):
        self._data.wipe_data(self.name)
