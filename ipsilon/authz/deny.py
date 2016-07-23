# Copyright (C) 2016 Ipsilon project Contributors, for license see COPYING

from ipsilon.authz.common import AuthzProviderBase
from ipsilon.authz.common import AuthzProviderInstaller
from ipsilon.util.plugin import PluginObject


class AuthzProvider(AuthzProviderBase):
    def __init__(self, *pargs):
        super(AuthzProvider, self).__init__(*pargs)
        self.name = 'deny'
        self.description = """
Authorization plugin to deny all requests. """
        self.new_config(self.name)

    def authorize_user(self, provplugname, provinfo, user, attributes):
        return False


class Installer(AuthzProviderInstaller):
    def __init__(self, *pargs):
        super(Installer, self).__init__()
        self.name = 'deny'
        self.pargs = pargs

    def install_args(self, group):
        group.add_argument('--authorization-deny', choices=['yes', 'no'],
                           default='no', dest='authz_deny',
                           help='Use the deny authorization provider')

    def configure(self, opts, changes):
        if opts['authz_deny'] != 'yes':
            return

        # Add configuration data to database
        po = PluginObject(*self.pargs)
        po.name = 'deny'
        po.wipe_data()
        po.wipe_config_values()

        # Update global config to add deny plugin
        po.is_enabled = True
        po.save_enabled_state()
