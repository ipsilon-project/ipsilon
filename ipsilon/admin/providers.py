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
from ipsilon.util.page import admin_protect, auth_protect
from ipsilon.providers.common import FACILITY
from ipsilon.admin.common import AdminPluginPage
from ipsilon.admin.common import AdminPage


class ProviderPlugins(AdminPage):
    def __init__(self, site, parent):
        super(ProviderPlugins, self).__init__(site)
        self._master = parent
        self.title = 'Identity Providers'
        self.url = '%s/providers' % parent.url
        self.facility = FACILITY
        parent.add_subtree('providers', self)

        for plugin in self._site[FACILITY]['available']:
            cherrypy.log.error('Admin provider plugin: %s' % plugin)
            obj = self._site[FACILITY]['available'][plugin]
            page = AdminPluginPage(obj, self._site, self)
            if hasattr(obj, 'admin'):
                obj.admin.mount(page)
            self.add_subtree(plugin, page)

    def root_with_msg(self, message=None, message_type=None):
        plugins = self._site[FACILITY]
        enabled_plugins = []
        for item in plugins['available']:
            plugin = plugins['available'][item]
            if plugin.is_enabled:
                enabled_plugins.append(item)
        return self._template('admin/providers.html', title=self.title,
                              baseurl=self.url,
                              message=message,
                              message_type=message_type,
                              available=plugins['available'],
                              enabled=enabled_plugins,
                              menu=self._master.menu)

    @auth_protect
    def root(self, *args, **kwargs):
        return self.root_with_msg()

    @admin_protect
    def enable(self, plugin):
        msg = None
        plugins = self._site[FACILITY]
        if plugin not in plugins['available']:
            msg = "Unknown plugin %s" % plugin
            return self.root_with_msg(msg, "error")
        obj = plugins['available'][plugin]
        if not obj.is_enabled:
            obj.enable(self._site)
            msg = "Plugin %s enabled" % obj.name
        return self.root_with_msg(msg, "success")
    enable.public_function = True

    @admin_protect
    def disable(self, plugin):
        msg = None
        plugins = self._site[FACILITY]
        if plugin not in plugins['available']:
            msg = "Unknown plugin %s" % plugin
            return self.root_with_msg(msg, "error")
        obj = plugins['available'][plugin]
        if obj.is_enabled:
            obj.disable(self._site)
            msg = "Plugin %s disabled" % obj.name
        return self.root_with_msg(msg, "success")
    disable.public_function = True
