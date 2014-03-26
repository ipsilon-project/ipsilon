#!/usr/bin/python
#
# Copyright (C) 2014  Simo Sorce <simo@redhat.com>
#
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import cherrypy
from ipsilon.util.page import Page
from ipsilon.util.page import admin_protect
from ipsilon.util.plugin import PluginObject
from ipsilon.admin.common import AdminPluginPage
from ipsilon.login.common import FACILITY


class LoginPluginsOrder(Page):

    def __init__(self, site, parent):
        super(LoginPluginsOrder, self).__init__(site)
        self.url = '%s/order' % parent.url
        self.menu = [parent]

    @admin_protect
    def GET(self, *args, **kwargs):
        return self._template('admin/login_order.html',
                              title='login plugins order',
                              name='admin_login_order_form',
                              menu=self.menu, action=self.url,
                              options=self._site[FACILITY]['enabled'])

    @admin_protect
    def POST(self, *args, **kwargs):
        message = "Nothing was modified."
        message_type = "info"
        valid = self._site[FACILITY]['enabled']

        if 'order' in kwargs:
            order = kwargs['order'].split(',')
            if len(order) != 0:
                new_values = []
                try:
                    for v in order:
                        val = v.strip()
                        if val not in valid:
                            error = "Invalid plugin name: %s" % val
                            raise ValueError(error)
                        new_values.append(val)
                    if len(new_values) < len(valid):
                        for val in valid:
                            if val not in new_values:
                                new_values.append(val)

                    po = PluginObject()
                    po.name = "global"
                    globalconf = dict()
                    globalconf['order'] = ','.join(new_values)
                    po.set_config(globalconf)
                    po.save_plugin_config(FACILITY)

                    # When all is saved update also live config
                    self._site[FACILITY]['enabled'] = new_values

                    message = "New configuration saved."
                    message_type = "success"

                except ValueError, e:
                    message = str(e)
                    message_type = "error"

                except Exception, e:  # pylint: disable=broad-except
                    message = "Failed to save data!"
                    message_type = "error"

        return self._template('admin/login_order.html',
                              message=message,
                              message_type=message_type,
                              title='login plugins order',
                              name='admin_login_order_form',
                              menu=self.menu, action=self.url,
                              options=self._site[FACILITY]['enabled'])

    def root(self, *args, **kwargs):
        cherrypy.log.error("method: %s" % cherrypy.request.method)
        op = getattr(self, cherrypy.request.method, self.GET)
        if callable(op):
            return op(*args, **kwargs)


class LoginPlugins(Page):
    def __init__(self, site, parent):
        super(LoginPlugins, self).__init__(site)
        self._master = parent
        self.title = 'Login Plugins'
        self.url = '%s/login' % parent.url
        self.facility = FACILITY
        parent.add_subtree('login', self)

        for plugin in self._site[FACILITY]['available']:
            cherrypy.log.error('Admin login plugin: %s' % plugin)
            obj = self._site[FACILITY]['available'][plugin]
            self.__dict__[plugin] = AdminPluginPage(obj, self._site, self)

        self.order = LoginPluginsOrder(self._site, self)

    def root(self, *args, **kwargs):
        login_plugins = self._site[FACILITY]
        return self._template('admin/login.html', title=self.title,
                              available=login_plugins['available'],
                              enabled=login_plugins['enabled'],
                              menu=self._master.menu)
