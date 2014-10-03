#!/usr/bin/python
#
# Copyright (C) 2014  Ipsilon Contributors see COPYING for license

import cherrypy
from ipsilon.util.page import Page
from ipsilon.util.page import admin_protect, auth_protect
from ipsilon.util.plugin import PluginObject
from ipsilon.admin.common import AdminPluginPage
from ipsilon.info.common import FACILITY


class InfoPluginsOrder(Page):

    def __init__(self, site, parent):
        super(InfoPluginsOrder, self).__init__(site, form=True)
        self.url = '%s/order' % parent.url
        self.menu = [parent]

    @admin_protect
    def GET(self, *args, **kwargs):
        opts = [p.name for p in self._site[FACILITY]['enabled']]
        return self._template('admin/info_order.html',
                              title='info plugins order',
                              name='admin_info_order_form',
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

                    po = PluginObject()
                    po.name = "global"
                    globalconf = dict()
                    globalconf['order'] = ','.join(new_names)
                    po.set_config(globalconf)
                    po.save_plugin_config(FACILITY)

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
        return self._template('admin/info_order.html',
                              message=message,
                              message_type=message_type,
                              title='info plugins order',
                              name='admin_info_order_form',
                              menu=self.menu, action=self.url,
                              options=opts)


class InfoPlugins(Page):
    def __init__(self, site, parent):
        super(InfoPlugins, self).__init__(site)
        self._master = parent
        self.title = 'Info Plugins'
        self.url = '%s/info' % parent.url
        self.facility = FACILITY
        parent.add_subtree('info', self)

        for plugin in self._site[FACILITY]['available']:
            cherrypy.log.error('Admin info plugin: %s' % plugin)
            obj = self._site[FACILITY]['available'][plugin]
            self.__dict__[plugin] = AdminPluginPage(obj, self._site, self)

        self.order = InfoPluginsOrder(self._site, self)

    def root_with_msg(self, message=None, message_type=None):
        info_plugins = self._site[FACILITY]
        ordered = []
        for p in info_plugins['enabled']:
            ordered.append(p.name)
        return self._template('admin/info.html', title=self.title,
                              message=message,
                              message_type=message_type,
                              available=info_plugins['available'],
                              enabled=ordered,
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
        if obj not in plugins['enabled']:
            obj.enable(self._site)
            msg = "Plugin %s enabled" % obj.name
        return self.root_with_msg(msg, "success")
    enable.exposed = True

    @admin_protect
    def disable(self, plugin):
        msg = None
        plugins = self._site[FACILITY]
        if plugin not in plugins['available']:
            msg = "Unknown plugin %s" % plugin
            return self.root_with_msg(msg, "error")
        obj = plugins['available'][plugin]
        if obj in plugins['enabled']:
            obj.disable(self._site)
            msg = "Plugin %s disabled" % obj.name
        return self.root_with_msg(msg, "success")
    disable.exposed = True
