#!/usr/bin/python
#
# Copyright (C) 2014 Ipsilon Project Contributors
#
# See the file named COPYING for the project license

from ipsilon.info.common import InfoProviderBase
from ipsilon.info.common import InfoProviderInstaller
from ipsilon.util.plugin import PluginObject
import pwd


class InfoProvider(InfoProviderBase):

    def __init__(self):
        super(InfoProvider, self).__init__()
        self.name = 'nss'

    def get_user_attrs(self, user):
        userattrs = None
        try:
            p = pwd.getpwnam(user)
            userattrs = {'uidNumber': p[2], 'gidNumber': p[3],
                         'gecos': p[4], 'homeDirectory': p[5],
                         'loginShell': p[6]}
        except KeyError:
            pass

        return userattrs


class Installer(InfoProviderInstaller):

    def __init__(self):
        super(Installer, self).__init__()
        self.name = 'nss'

    def install_args(self, group):
        group.add_argument('--info-nss', choices=['yes', 'no'], default='no',
                           help='Use passwd data to populate user attrs')

    def configure(self, opts):
        if opts['info_nss'] != 'yes':
            return

        # Add configuration data to database
        po = PluginObject()
        po.name = 'nss'
        po.wipe_data()
        po.wipe_config_values(self.facility)

        # Replace global config, only one plugin info can be used
        po.name = 'global'
        globalconf = po.get_plugin_config(self.facility)
        if 'order' in globalconf:
            order = globalconf['order'].split(',')
        else:
            order = []
        order.append('nss')
        globalconf['order'] = ','.join(order)
        po.set_config(globalconf)
        po.save_plugin_config(self.facility)
