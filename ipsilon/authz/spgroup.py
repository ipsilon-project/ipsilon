# Copyright (C) 2016 Ipsilon project Contributors, for license see COPYING

from ipsilon.authz.common import AuthzProviderBase
from ipsilon.authz.common import AuthzProviderInstaller
from ipsilon.util.plugin import PluginObject
from ipsilon.util import config as pconfig


class AuthzProvider(AuthzProviderBase):
    def __init__(self, *pargs):
        super(AuthzProvider, self).__init__(*pargs)
        self.name = 'spgroup'
        self.description = """
Authorization plugin that allows access based on user groups.
This plugin will decline to authorize users not in the prerequisite group,
rather than reject them outright."""
        self.new_config(
            self.name,
            pconfig.String(
                'prefix',
                'Group name prefix',
                ''),
            pconfig.String(
                'suffix',
                'Group name suffix',
                '')
        )

    @property
    def prefix(self):
        return self.get_config_value('prefix')

    @property
    def suffix(self):
        return self.get_config_value('suffix')

    def authorize_user(self, provplugname, provinfo, user, attributes):
        if 'groups' in attributes:
            groups = attributes['groups']
        elif '_groups' in attributes:
            groups = attributes['_groups']
        else:
            return None

        provname = provinfo.get('name', None)
        if provname is None:
            return None

        groupname = '%s%s%s' % (self.prefix, provname, self.suffix)

        self.debug('Looking for group "%s" in user groups' % groupname)

        if groupname in groups:
            return True
        else:
            return None


class Installer(AuthzProviderInstaller):
    def __init__(self, *pargs):
        super(Installer, self).__init__()
        self.name = 'spgroup'
        self.pargs = pargs

    def install_args(self, group):
        group.add_argument('--authorization-spgroup', choices=['yes', 'no'],
                           default='no', dest='authz_spgroup',
                           help='Use the spgroup authorization provider')
        group.add_argument('--authorization-spgroup-prefix', action='store',
                           dest='authz_spgroup_prefix',
                           help='Group name prefix')
        group.add_argument('--authorization-spgroup-suffix', action='store',
                           dest='authz_spgroup_suffix',
                           help='Group name suffix')

    def configure(self, opts, changes):
        if opts['authz_spgroup'] != 'yes':
            return

        # Add configuration data to database
        po = PluginObject(*self.pargs)
        po.name = 'spgroup'
        po.wipe_data()
        po.wipe_config_values()
        config = dict()
        if 'authz_spgroup_prefix' in opts:
            config['prefix'] = opts['authz_spgroup_prefix']
        if 'authz_spgroup_suffix' in opts:
            config['suffix'] = opts['authz_spgroup_suffix']
        po.save_plugin_config(config)

        # Update global config to add spgroup plugin
        po.is_enabled = True
        po.save_enabled_state()
