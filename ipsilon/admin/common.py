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


class AdminPluginPage(Page):

    def __init__(self, obj, site, parent):
        super(AdminPluginPage, self).__init__(site, form=True)
        self._obj = obj
        self.title = '%s plugin' % obj.name
        self.url = '%s/%s' % (parent.url, obj.name)
        self.facility = parent.facility
        self.menu = [parent]
        self.back = parent.url

        # Get the defaults
        self.plugin_config = obj.get_config_desc()
        if not self.plugin_config:
            self.plugin_config = dict()

        # Now overlay the actual config
        for option in self.plugin_config:
            self.plugin_config[option][2] = obj.get_config_value(option)

        self.options_order = []
        if hasattr(obj, 'conf_opt_order'):
            self.options_order = obj.conf_opt_order

        # append any undefined options
        add = []
        for k in self.plugin_config.keys():
            if k not in self.options_order:
                add.append(k)
        if len(add):
            add.sort()
            for k in add:
                self.options_order.append(k)

    @admin_protect
    def GET(self, *args, **kwargs):
        return self._template('admin/plugin_config.html', title=self.title,
                              name='admin_%s_%s_form' % (self.facility,
                                                         self._obj.name),
                              menu=self.menu, action=self.url, back=self.back,
                              options_order=self.options_order,
                              options=self.plugin_config)

    @admin_protect
    def POST(self, *args, **kwargs):

        message = "Nothing was modified."
        message_type = "info"
        new_values = dict()

        for key, value in kwargs.iteritems():
            if key in self.plugin_config:
                if value != self.plugin_config[key][2]:
                    cherrypy.log.error("Storing [%s]: %s = %s" %
                                       (self._obj.name, key, value))
                    new_values[key] = value

        if len(new_values) != 0:
            # First we try to save in the database
            try:
                self._obj.save_plugin_config(self.facility, new_values)
                message = "New configuration saved."
                message_type = "success"
            except Exception:  # pylint: disable=broad-except
                message = "Failed to save data!"
                message_type = "error"

            # And only if it succeeds we change the live object
            for name, value in new_values.items():
                self._obj.set_config_value(name, value)
                self.plugin_config[name][2] = value

        return self._template('admin/plugin_config.html', title=self.title,
                              message=message,
                              message_type=message_type,
                              name='admin_%s_%s_form' % (self.facility,
                                                         self._obj.name),
                              menu=self.menu, action=self.url,
                              options=self.plugin_config)


class Admin(Page):

    def __init__(self, site, mount):
        super(Admin, self).__init__(site)
        self.url = '%s/%s' % (self.basepath, mount)
        self.menu = []

    def root(self, *args, **kwargs):
        return self._template('admin/index.html',
                              title='Configuration',
                              menu=self.menu)

    def add_subtree(self, name, page):
        self.__dict__[name] = page
        self.menu.append(page)

    def del_subtree(self, name):
        self.menu.remove(self.__dict__[name])
        del self.__dict__[name]
