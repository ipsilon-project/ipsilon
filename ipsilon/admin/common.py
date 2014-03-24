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

from ipsilon.util.data import Store
from ipsilon.util.page import Page
from ipsilon.util.page import admin_protect
from ipsilon.util.plugin import PluginObject
import cherrypy
from ipsilon.login.common import FACILITY as LOGIN_FACILITY


class LoginPluginPage(Page):

    def __init__(self, obj, site, baseurl):
        super(LoginPluginPage, self).__init__(site)
        self._obj = obj
        self.url = '%s/%s' % (baseurl, obj.name)

        # Get the defaults
        self.plugin_config = obj.get_config_desc()
        if not self.plugin_config:
            self.plugin_config = []

        # Now overlay the actual config
        for option in self.plugin_config:
            self.plugin_config[option][2] = obj.get_config_value(option)

    @admin_protect
    def GET(self, *args, **kwargs):
        return self._template('admin/login_plugin.html',
                              title='%s plugin' % self._obj.name,
                              name='admin_login_%s_form' % self._obj.name,
                              action=self.url,
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
                store = Store()
                store.save_plugin_config(LOGIN_FACILITY,
                                         self._obj.name, new_values)
                message = "New configuration saved."
                message_type = "success"
            except Exception:  # pylint: disable=broad-except
                message = "Failed to save data!"
                message_type = "error"

            # And only if it succeeds we change the live object
            for name, value in new_values.items():
                self._obj.set_config_value(name, value)
                self.plugin_config[name][2] = value

        return self._template('admin/login_plugin.html',
                              message=message,
                              message_type=message_type,
                              title='%s plugin' % self._obj.name,
                              name='admin_login_%s_form' % self._obj.name,
                              action=self.url,
                              options=self.plugin_config)

    def root(self, *args, **kwargs):
        cherrypy.log.error("method: %s" % cherrypy.request.method)
        op = getattr(self, cherrypy.request.method, self.GET)
        if callable(op):
            return op(*args, **kwargs)


class LoginPluginsOrder(Page):

    def __init__(self, site, baseurl):
        super(LoginPluginsOrder, self).__init__(site)
        self.url = '%s/order' % baseurl

    @admin_protect
    def GET(self, *args, **kwargs):
        return self._template('admin/login_order.html',
                              title='login plugins order',
                              name='admin_login_order_form',
                              action=self.url,
                              options=self._site[LOGIN_FACILITY]['enabled'])

    @admin_protect
    def POST(self, *args, **kwargs):
        message = "Nothing was modified."
        message_type = "info"
        valid = self._site[LOGIN_FACILITY]['enabled']

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
                    po.save_plugin_config(LOGIN_FACILITY)

                    # When all is saved update also live config
                    self._site[LOGIN_FACILITY]['enabled'] = new_values

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
                              action=self.url,
                              options=self._site[LOGIN_FACILITY]['enabled'])

    def root(self, *args, **kwargs):
        cherrypy.log.error("method: %s" % cherrypy.request.method)
        op = getattr(self, cherrypy.request.method, self.GET)
        if callable(op):
            return op(*args, **kwargs)


class LoginPlugins(Page):
    def __init__(self, site, baseurl):
        super(LoginPlugins, self).__init__(site)
        self.url = '%s/login' % baseurl

        for plugin in self._site[LOGIN_FACILITY]['available']:
            cherrypy.log.error('Admin login plugin: %s' % plugin)
            obj = self._site[LOGIN_FACILITY]['available'][plugin]
            self.__dict__[plugin] = LoginPluginPage(obj, self._site, self.url)

        self.order = LoginPluginsOrder(self._site, self.url)


class Admin(Page):

    def __init__(self, *args, **kwargs):
        super(Admin, self).__init__(*args, **kwargs)
        self.url = '%s/admin' % self.basepath
        self.login = LoginPlugins(self._site, self.url)

    def root(self, *args, **kwargs):
        login_plugins = self._site[LOGIN_FACILITY]
        return self._template('admin/index.html', title='Administration',
                              available=login_plugins['available'],
                              enabled=login_plugins['enabled'])
