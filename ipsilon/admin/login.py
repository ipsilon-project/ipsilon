# Copyright (C) 2014  Ipsilon Contributors see COPYING for license

from ipsilon.admin.loginstack import LoginStackPlugins
from ipsilon.login.common import FACILITY


class LoginPlugins(LoginStackPlugins):
    def __init__(self, site, parent):
        super(LoginPlugins, self).__init__('login', site, parent, FACILITY)
        self.title = 'Login Plugins'
