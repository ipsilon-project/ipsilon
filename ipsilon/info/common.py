# Copyright (C) 2014 Ipsilon Project Contributors
#
# See the file named COPYING for the project license

from ipsilon.util.log import Log
from ipsilon.util.plugin import PluginInstaller, PluginLoader
from ipsilon.util.plugin import PluginObject, PluginConfig


class InfoProviderBase(PluginConfig, PluginObject):

    def __init__(self, *pargs):
        PluginConfig.__init__(self)
        PluginObject.__init__(self, *pargs)

    def get_user_attrs(self, user):
        raise NotImplementedError


class InfoMapping(Log):

    def __init__(self):
        self.standard_attributes = {
            'fullname': 'Full Name',
            'nickname': 'Nickname',
            'surname': 'Last Name',
            'firstname': 'First Name',
            'title': 'Title',
            'dob': 'Date of Birth',
            'email': 'E-mail Address',
            'gender': 'Gender',
            'postcode': 'Postal Code',
            'street': 'Street Address',
            'state': 'State or Province',
            'country': 'Country',
            'phone': 'Telephone Number',
            'language': 'Language',
            'timezone': 'Time Zone',
        }
        self.mapping = dict()

    def set_mapping(self, attrs_map):
        self.mapping = attrs_map

    def display_name(self, name):
        if name in self.standard_attributes:
            return self.standard_attributes[name]
        return name

    def map_attrs(self, attrs):
        s = dict()
        e = dict()
        for a in attrs:
            if a in self.mapping:
                s[self.mapping[a]] = attrs[a]
            else:
                e[a] = attrs[a]

        return s, e


FACILITY = 'info_config'


class Info(Log):

    def __init__(self, site):
        self._site = site

        plugins = PluginLoader(Info, FACILITY, 'InfoProvider')
        plugins.get_plugin_data()
        self._site[FACILITY] = plugins

        available = plugins.available.keys()
        self.debug('Available info providers: %s' % str(available))

        for item in plugins.enabled:
            self.debug('Info plugin in enabled list: %s' % item)
            if item not in plugins.available:
                self.debug('Info Plugin %s not found' % item)
                continue
            plugins.available[item].enable()

    def get_user_attrs(self, user, requested=None):
        plugins = self._site[FACILITY].available
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
        pi = PluginInstaller(InfoProviderInstall, FACILITY)
        self.plugins = pi.get_plugins()
