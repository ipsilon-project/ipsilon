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


def save_enabled_plugins(names):
    po = PluginObject()
    po.name = "global"
    globalconf = dict()
    globalconf['order'] = ','.join(names)
    po.set_config(globalconf)
    po.save_plugin_config(FACILITY)


class LoginPluginsOrder(Page):

    def __init__(self, site, parent):
        super(LoginPluginsOrder, self).__init__(site, form=True)
        self.url = '%s/order' % parent.url
        self.menu = [parent]

    def _reorder_plugins(self, order):
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

    @admin_protect
    def GET(self, *args, **kwargs):
        opts = [p.name for p in self._site[FACILITY]['enabled']]
        return self._template('admin/login_order.html',
                              title='login plugins order',
                              name='admin_login_order_form',
                              menu=self.menu, action=self.url,
                              options=opts)

    @admin_protect
    def POST(self, *args, **kwargs):
        message = "Nothing was modified."
        message_type = "info"
        plugins_by_name = {p.name: p for p in self._site[FACILITY]['enabled']}

        if 'order' in kwargs:
            order = kwargs['order'].split(',')
            if len(order) != 0:
                new_names = []
                new_plugins = []
                try:
                    for v in order:
                        val = v.strip()
                        if val not in plugins_by_name:
                            error = "Invalid plugin name: %s" % val
                            raise ValueError(error)
                        new_names.append(val)
                        new_plugins.append(plugins_by_name[val])
                    if len(new_names) < len(plugins_by_name):
                        for val in plugins_by_name:
                            if val not in new_names:
                                new_names.append(val)
                                new_plugins.append(plugins_by_name[val])

                    save_enabled_plugins(new_names)
                    self._reorder_plugins(new_names)

                    # When all is saved update also live config. The
                    # live config is a list of the actual plugin
                    # objects.
                    self._site[FACILITY]['enabled'] = new_plugins

                    message = "New configuration saved."
                    message_type = "success"

                except ValueError, e:
                    message = str(e)
                    message_type = "error"

                except Exception, e:  # pylint: disable=broad-except
                    message = "Failed to save data!"
                    message_type = "error"

        opts = [p.name for p in self._site[FACILITY]['enabled']]
        return self._template('admin/login_order.html',
                              message=message,
                              message_type=message_type,
                              title='login plugins order',
                              name='admin_login_order_form',
                              menu=self.menu, action=self.url,
                              options=opts)


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

    def root_with_msg(self, message=None, message_type=None):
        login_plugins = self._site[FACILITY]
        ordered = []
        for p in login_plugins['enabled']:
            ordered.append(p.name)
        return self._template('admin/login.html', title=self.title,
                              message=message,
                              message_type=message_type,
                              available=login_plugins['available'],
                              enabled=ordered,
                              menu=self._master.menu)

    def root(self, *args, **kwargs):
        return self.root_with_msg()

    def enable(self, plugin):
        msg = None
        plugins = self._site[FACILITY]
        if plugin not in plugins['available']:
            msg = "Unknown plugin %s" % plugin
            return self.root_with_msg(msg, "error")
        obj = plugins['available'][plugin]
        if obj not in plugins['enabled']:
            obj.enable(self._site)
            save_enabled_plugins(list(x.name for x in plugins['enabled']))
            msg = "Plugin %s enabled" % obj.name
        return self.root_with_msg(msg, "success")
    enable.exposed = True

    def disable(self, plugin):
        msg = None
        plugins = self._site[FACILITY]
        if plugin not in plugins['available']:
            msg = "Unknown plugin %s" % plugin
            return self.root_with_msg(msg, "error")
        obj = plugins['available'][plugin]
        if obj in plugins['enabled']:
            obj.disable(self._site)
            save_enabled_plugins(list(x.name for x in plugins['enabled']))
            msg = "Plugin %s disabled" % obj.name
        return self.root_with_msg(msg, "success")
    disable.exposed = True
