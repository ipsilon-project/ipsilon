# Copyright (C) 2014  Ipsilon Contributors see COPYING for license

from ipsilon.admin.common import AdminPlugins
from ipsilon.login.common import FACILITY


class LoginPlugins(AdminPlugins):
    def __init__(self, site, parent):
        super(LoginPlugins, self).__init__('login', site, parent, FACILITY)
        self.title = 'Login Plugins'
