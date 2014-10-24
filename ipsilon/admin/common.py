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


class AdminPage(Page):

    def __init__(self, *args, **kwargs):
        super(AdminPage, self).__init__(*args, **kwargs)
        self.default_headers.update({
            'Cache-Control': 'no-cache, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': 'Thu, 01 Dec 1994 16:00:00 GMT',
        })
        self.auth_protect = True


class AdminPluginConfig(AdminPage):

    def __init__(self, po, site, parent):
        super(AdminPluginConfig, self).__init__(site, form=True)
        self._po = po
        self.title = '%s plugin' % po.name
        self.url = '%s/%s' % (parent.url, po.name)
        self.facility = parent.facility
        self.menu = [parent]
        self.back = parent.url

        # Get the defaults
        options = po.get_config_desc()
        if options is None:
            options = dict()

        self.options_order = []
        if hasattr(po, 'conf_opt_order'):
            self.options_order = po.conf_opt_order

        # append any undefined options
        add = []
        for k in options.keys():
            if k not in self.options_order:
                add.append(k)
        if len(add):
            add.sort()
            for k in add:
                self.options_order.append(k)

    def root_with_msg(self, message=None, message_type=None):
        return self._template('admin/plugin_config.html', title=self.title,
                              menu=self.menu, action=self.url, back=self.back,
                              message=message, message_type=message_type,
                              name='admin_%s_%s_form' % (self.facility,
                                                         self._po.name),
                              options_order=self.options_order,
                              plugin=self._po)

    @admin_protect
    def GET(self, *args, **kwargs):
        return self.root_with_msg()

    @admin_protect
    def POST(self, *args, **kwargs):

        message = "Nothing was modified."
        message_type = "info"
        new_values = dict()

        # Get the defaults
        options = self._po.get_config_desc()
        if options is None:
            options = dict()

        for key, value in kwargs.iteritems():
            if key in options:
                if value != self._po.get_config_value(key):
                    cherrypy.log.error("Storing [%s]: %s = %s" %
                                       (self._po.name, key, value))
                    new_values[key] = value

        if len(new_values) != 0:
            # First we try to save in the database
            try:
                self._po.save_plugin_config(self.facility, new_values)
                message = "New configuration saved."
                message_type = "success"
            except Exception:  # pylint: disable=broad-except
                message = "Failed to save data!"
                message_type = "error"

            # And only if it succeeds we change the live object
            self._po.refresh_plugin_config(self.facility)

        return self.root_with_msg(message=message,
                                  message_type=message_type)


class AdminPluginsOrder(AdminPage):

    def __init__(self, site, parent, facility):
        super(AdminPluginsOrder, self).__init__(site, form=True)
        self.parent = parent
        self.facility = facility
        self.url = '%s/order' % parent.url
        self.menu = [parent]

    @admin_protect
    def GET(self, *args, **kwargs):
        return self.parent.root_with_msg()

    def _get_enabled_by_name(self):
        by_name = dict()
        for p in self._site[self.facility]['available'].values():
            if p.is_enabled:
                by_name[p.name] = p
        return by_name

    @admin_protect
    def POST(self, *args, **kwargs):
        message = "Nothing was modified."
        message_type = "info"
        by_name = self._get_enabled_by_name()

        if 'order' in kwargs:
            order = kwargs['order'].split(',')
            if len(order) != 0:
                new_names = []
                new_plugins = []
                try:
                    for v in order:
                        val = v.strip()
                        if val not in by_name:
                            error = "Invalid plugin name: %s" % val
                            raise ValueError(error)
                        new_names.append(val)
                        new_plugins.append(by_name[val])
                    if len(new_names) < len(by_name):
                        for val in by_name:
                            if val not in new_names:
                                new_names.append(val)
                                new_plugins.append(by_name[val])

                    self.parent.save_enabled_plugins(new_names)
                    self.parent.reorder_plugins(new_names)

                    # When all is saved update also live config. The
                    # live config is a list of the actual plugin
                    # objects.
                    self._site[self.facility]['enabled'] = new_plugins

                    message = "New configuration saved."
                    message_type = "success"

                except ValueError, e:
                    message = str(e)
                    message_type = "error"

                except Exception, e:  # pylint: disable=broad-except
                    message = "Failed to save data!"
                    message_type = "error"

        return self.parent.root_with_msg(message=message,
                                         message_type=message_type)


class AdminPlugins(AdminPage):
    def __init__(self, name, site, parent, facility, ordered=True):
        super(AdminPlugins, self).__init__(site)
        self._master = parent
        self.name = name
        self.title = '%s plugins' % name
        self.url = '%s/%s' % (parent.url, name)
        self.facility = facility
        self.template = 'admin/plugins.html'
        self.order = None
        parent.add_subtree(name, self)

        for plugin in self._site[facility]['available']:
            cherrypy.log.error('Admin info plugin: %s' % plugin)
            obj = self._site[facility]['available'][plugin]
            page = AdminPluginConfig(obj, self._site, self)
            if hasattr(obj, 'admin'):
                obj.admin.mount(page)
            self.add_subtree(plugin, page)

        if ordered:
            self.order = AdminPluginsOrder(self._site, self, facility)

    def save_enabled_plugins(self, names):
        po = PluginObject()
        po.name = "global"
        globalconf = dict()
        globalconf['order'] = ','.join(names)
        po.set_config(globalconf)
        po.save_plugin_config(self.facility)

    def reorder_plugins(self, names):
        return

    def root_with_msg(self, message=None, message_type=None):
        plugins = self._site[self.facility]
        enabled = []
        if self.order:
            for plugin in plugins['enabled']:
                if plugin.is_enabled:
                    enabled.append(plugin.name)
        else:
            for _, plugin in plugins['available'].iteritems():
                if plugin.is_enabled:
                    enabled.append(plugin.name)

        targs = {'title': self.title,
                 'menu': self._master.menu,
                 'message': message,
                 'message_type': message_type,
                 'available': plugins['available'],
                 'enabled': enabled,
                 'baseurl': self.url}
        if self.order:
            targs['order_name'] = '%s_order_form' % self.name
            targs['order_action'] = self.order.url

        # pylint: disable=star-args
        return self._template(self.template, **targs)

    def root(self, *args, **kwargs):
        return self.root_with_msg()

    @admin_protect
    def enable(self, plugin):
        msg = None
        plugins = self._site[self.facility]
        if plugin not in plugins['available']:
            msg = "Unknown plugin %s" % plugin
            return self.root_with_msg(msg, "error")
        obj = plugins['available'][plugin]
        if not obj.is_enabled:
            obj.enable(self._site)
            if self.order:
                enabled = list(x.name for x in plugins['enabled'])
                self.save_enabled_plugins(enabled)
            msg = "Plugin %s enabled" % obj.name
        return self.root_with_msg(msg, "success")
    enable.public_function = True

    @admin_protect
    def disable(self, plugin):
        msg = None
        plugins = self._site[self.facility]
        if plugin not in plugins['available']:
            msg = "Unknown plugin %s" % plugin
            return self.root_with_msg(msg, "error")
        obj = plugins['available'][plugin]
        if obj.is_enabled:
            obj.disable(self._site)
            if self.order:
                enabled = list(x.name for x in plugins['enabled'])
                self.save_enabled_plugins(enabled)
            msg = "Plugin %s disabled" % obj.name
        return self.root_with_msg(msg, "success")
    disable.public_function = True


class Admin(AdminPage):

    def __init__(self, site, mount):
        super(Admin, self).__init__(site)
        self.title = 'Home'
        self.mount = mount
        self.url = '%s/%s' % (self.basepath, mount)
        self.menu = [self]

    def root(self, *args, **kwargs):
        return self._template('admin/index.html',
                              title='Configuration',
                              baseurl=self.url,
                              menu=self.menu)

    def add_subtree(self, name, page):
        self.__dict__[name] = page
        self.menu.append(page)

    def del_subtree(self, name):
        self.menu.remove(self.__dict__[name])
        del self.__dict__[name]

    def get_menu_urls(self):
        urls = dict()
        for item in self.menu:
            name = getattr(item, 'name', None)
            if name:
                urls['%s_url' % name] = cherrypy.url('/%s/%s' % (self.mount,
                                                                 name))
        return urls

    @admin_protect
    def scheme(self):
        cherrypy.response.headers.update({'Content-Type': 'image/svg+xml'})
        urls = self.get_menu_urls()
        # pylint: disable=star-args
        return self._template('admin/ipsilon-scheme.svg', **urls)
    scheme.public_function = True
