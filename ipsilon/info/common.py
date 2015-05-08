# Copyright (C) 2014 Ipsilon project Contributors, for license see COPYING

from ipsilon.util.log import Log
from ipsilon.util.plugin import PluginInstaller, PluginLoader
from ipsilon.util.plugin import PluginObject
from ipsilon.util.config import ConfigHelper


class InfoProviderBase(ConfigHelper, PluginObject):

    def __init__(self, *pargs):
        ConfigHelper.__init__(self)
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

    def display_name(self, name):
        if name in self.standard_attributes:
            return self.standard_attributes[name]
        return name


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
            try:
                plugins.available[item].enable()
            except Exception as e:  # pylint: disable=broad-except
                while item in plugins.enabled:
                    plugins.enabled.remove(item)
                self.debug("Info Plugin %s couldn't be enabled: %s" % (
                    item, str(e)))

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

    def validate_args(self, args):
        return

    def unconfigure(self, opts, changes):
        return

    def configure(self, opts, changes):
        raise NotImplementedError


class InfoProviderInstall(object):

    def __init__(self):
        pi = PluginInstaller(InfoProviderInstall, FACILITY)
        self.plugins = pi.get_plugins()
