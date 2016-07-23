# Copyright (C) 2016 Ipsilon project Contributors, for license see COPYING

from ipsilon.authz.common import AuthzProviderBase
from ipsilon.authz.common import AuthzProviderInstaller
from ipsilon.util.plugin import PluginObject


class AuthzProvider(AuthzProviderBase):
    def __init__(self, *pargs):
        super(AuthzProvider, self).__init__(*pargs)
        self.name = 'allow'
        self.description = """
Authorization plugin to allow all requests. """
        self.new_config(self.name)

    def authorize_user(self, provplugname, provinfo, user, attributes):
        return True


class Installer(AuthzProviderInstaller):
    def __init__(self, *pargs):
        super(Installer, self).__init__()
        self.name = 'allow'
        self.pargs = pargs

    def install_args(self, group):
        group.add_argument('--authorization-allow', choices=['yes', 'no'],
                           default='yes', dest='authz_allow',
                           help='Use the allow authorization provider')

    def configure(self, opts, changes):
        if opts['authz_allow'] != 'yes':
            return

        # Add configuration data to database
        po = PluginObject(*self.pargs)
        po.name = 'allow'
        po.wipe_data()
        po.wipe_config_values()

        # Update global config to add allow plugin
        po.is_enabled = True
        po.save_enabled_state()
