# Copyright (C) 2016 Ipsilon Contributors, for license see COPYING

from ipsilon.admin.loginstack import LoginStackPlugins
from ipsilon.authz.common import FACILITY


class AuthzPlugins(LoginStackPlugins):
    def __init__(self, site, parent):
        super(AuthzPlugins, self).__init__('authz', site, parent, FACILITY)
        self.title = 'Authorization Plugins'
