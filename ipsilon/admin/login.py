#!/usr/bin/python
#
# Copyright (C) 2014  Ipsilon Contributors see COPYING for license

from ipsilon.admin.common import AdminPlugins
from ipsilon.login.common import FACILITY


class LoginPlugins(AdminPlugins):
    def __init__(self, site, parent):
        super(LoginPlugins, self).__init__('login', site, parent, FACILITY)
        self.title = 'Login Plugins'

    def reorder_plugins(self, order):
        plugins = self._site[FACILITY]['available']
        root = self._site[FACILITY]['root']
        prev_obj = None
        for name in order:
            if prev_obj is None:
                root.first_login = plugins[name]
            else:
                prev_obj.next_login = plugins[name]
            prev_obj = plugins[name]
        prev_obj.next_login = None
