# Copyright (C) 2014 Ipsilon project Contributors, for license see COPYING

import cherrypy
import logging
from ipsilon.util.page import Page
from ipsilon.util.page import admin_protect
from ipsilon.util.endpoint import allow_iframe
from ipsilon.util import config as pconfig


ADMIN_STATUS_OK = "success"
ADMIN_STATUS_ERROR = "danger"
ADMIN_STATUS_WARN = "warning"


class AdminError(Exception):
    def __init__(self, message):
        super(AdminError, self).__init__(message)
        self.message = message

    def __str__(self):
        return str(self.message)


class AdminPage(Page):

    def __init__(self, *args, **kwargs):
        super(AdminPage, self).__init__(*args, **kwargs)
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

    def root_with_msg(self, message=None, message_type=None):
        return self._template('admin/option_config.html', title=self.title,
                              menu=self.menu, action=self.url, back=self.back,
                              message=message, message_type=message_type,
                              name='admin_%s_%s_form' % (self.facility,
                                                         self._po.name),
                              config=self._po.get_config_obj())

    @admin_protect
    def GET(self, *args, **kwargs):
        return self.root_with_msg()

    @admin_protect
    def POST(self, *args, **kwargs):

        if self._po.is_readonly:
            return self.root_with_msg(
                message="Configuration is marked Read-Only",
                message_type=ADMIN_STATUS_WARN)

        message = "Nothing was modified."
        message_type = "info"
        new_db_values = dict()

        conf = self._po.get_config_obj()

        for name, option in conf.iteritems():
            if name in kwargs:
                value = kwargs[name]
                if isinstance(option, pconfig.List):
                    value = [x.strip() for x in value.split('\n')]
                elif isinstance(option, pconfig.Condition):
                    value = True
            else:
                if isinstance(option, pconfig.Condition):
                    value = False
                elif isinstance(option, pconfig.Choice):
                    value = list()
                    for a in option.get_allowed():
                        aname = '%s_%s' % (name, a)
                        if aname in kwargs:
                            value.append(a)
                elif isinstance(option, pconfig.MappingList):
                    value = get_mapping_list_value(name,
                                                   option.get_value(),
                                                   **kwargs)
                    if value is None:
                        continue
                elif isinstance(option, pconfig.ComplexList):
                    value = get_complex_list_value(name,
                                                   option.get_value(),
                                                   **kwargs)
                    if value is None:
                        continue
                else:
                    continue

            if value != option.get_value():
                cherrypy.log.error("Storing [%s]: %s = %s" %
                                   (self._po.name, name, value),
                                   severity=logging.DEBUG)
            option.set_value(value)
            new_db_values[name] = option.export_value()

        if len(new_db_values) != 0:
            # First we try to save in the database
            try:
                self._po.save_plugin_config(new_db_values)
                message = "New configuration saved."
                message_type = ADMIN_STATUS_OK
            except Exception as e:  # pylint: disable=broad-except
                self.error('Failed to save data: %s' % e)
                message = "Failed to save data!"
                message_type = ADMIN_STATUS_ERROR

            # Then refresh the actual objects
            self._po.refresh_plugin_config()

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

    @admin_protect
    def POST(self, *args, **kwargs):

        if self._site[self.facility].is_readonly:
            return self.parent.root_with_msg(
                message="Configuration is marked Read-Only",
                message_type=ADMIN_STATUS_WARN)

        message = "Nothing was modified."
        message_type = "info"
        changed = None
        cur_enabled = self._site[self.facility].enabled

        if 'order' in kwargs:
            order = kwargs['order'].split(',')
            if len(order) != 0:
                new_order = []
                try:
                    for v in order:
                        val = v.strip()
                        if val not in cur_enabled:
                            error = "Invalid plugin name: %s" % val
                            raise ValueError(error)
                        new_order.append(val)
                    if len(new_order) < len(cur_enabled):
                        for val in cur_enabled:
                            if val not in new_order:
                                new_order.append(val)

                    self.parent.save_enabled_plugins(new_order)

                    # When all is saved update also live config. The
                    # live config is the ordered list of plugin names.
                    self._site[self.facility].refresh_enabled()

                    message = "New configuration saved."
                    message_type = ADMIN_STATUS_OK

                    changed = dict()
                    self.debug('%s -> %s' % (cur_enabled, new_order))
                    for i in range(0, len(cur_enabled)):
                        if cur_enabled[i] != new_order[i]:
                            changed[cur_enabled[i]] = 'reordered'

                except ValueError, e:
                    message = str(e)
                    message_type = ADMIN_STATUS_ERROR

                except Exception as e:  # pylint: disable=broad-except
                    self.error('Failed to save data: %s' % e)
                    message = "Failed to save data!"
                    message_type = ADMIN_STATUS_ERROR

        return self.parent.root_with_msg(message=message,
                                         message_type=message_type,
                                         changed=changed)


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

        if self._site[facility] is None:
            return

        for plugin in self._site[facility].available:
            cherrypy.log.error('Admin info plugin: %s' % plugin,
                               severity=logging.DEBUG)
            obj = self._site[facility].available[plugin]
            page = AdminPluginConfig(obj, self._site, self)
            if hasattr(obj, 'admin'):
                obj.admin.mount(page)
            self.add_subtree(plugin, page)

        if ordered:
            self.order = AdminPluginsOrder(self._site, self, facility)

    def save_enabled_plugins(self, names):
        self._site[self.facility].save_enabled(names)

    def root_with_msg(self, message=None, message_type=None, changed=None):
        plugins = self._site[self.facility]

        if changed is None:
            changed = dict()

        targs = {'title': self.title,
                 'menu': self._master.menu,
                 'message': message,
                 'message_type': message_type,
                 'available': plugins.available,
                 'enabled': plugins.enabled,
                 'changed': changed,
                 'baseurl': self.url,
                 'newurl': self.url}
        if self.order:
            targs['order_name'] = '%s_order_form' % self.name
            targs['order_action'] = self.order.url

        return self._template(self.template, **targs)

    def root(self, *args, **kwargs):
        return self.root_with_msg()

    def _get_plugin_obj(self, plugin):
        plugins = self._site[self.facility]
        if plugins.is_readonly:
            msg = "Configuration is marked Read-Only"
            raise AdminError(msg)
        if plugin not in plugins.available:
            msg = "Unknown plugin %s" % plugin
            raise AdminError(msg)
        obj = plugins.available[plugin]
        if obj.is_readonly:
            msg = "Plugin Configuration is marked Read-Only"
            raise AdminError(msg)
        return obj

    @admin_protect
    def enable(self, plugin):
        msg = None
        try:
            obj = self._get_plugin_obj(plugin)
        except AdminError, e:
            return self.root_with_msg(str(e), ADMIN_STATUS_WARN)
        if not obj.is_enabled:
            try:
                obj.enable()
            except Exception as e:  # pylint: disable=broad-except
                return self.root_with_msg(str(e), ADMIN_STATUS_WARN)
            obj.save_enabled_state()
            msg = "Plugin %s enabled" % obj.name
        return self.root_with_msg(msg, ADMIN_STATUS_OK,
                                  changed={obj.name: 'enabled'})
    enable.public_function = True

    @admin_protect
    def disable(self, plugin):
        msg = None
        try:
            obj = self._get_plugin_obj(plugin)
        except AdminError, e:
            return self.root_with_msg(str(e), ADMIN_STATUS_WARN)
        if obj.is_enabled:
            try:
                obj.disable()
            except Exception as e:  # pylint: disable=broad-except
                return self.root_with_msg(str(e), ADMIN_STATUS_WARN)
            obj.save_enabled_state()
            msg = "Plugin %s disabled" % obj.name
        return self.root_with_msg(msg, ADMIN_STATUS_OK,
                                  changed={obj.name: 'disabled'})
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
    @allow_iframe
    def scheme(self):
        cherrypy.response.headers.update({'Content-Type': 'image/svg+xml'})
        urls = self.get_menu_urls()
        return str(self._template('admin/ipsilon-scheme.svg', **urls))
    scheme.public_function = True


def get_complex_list_value(name, old_value, **kwargs):
    delete = list()
    change = dict()
    for key, val in kwargs.iteritems():
        if not key.startswith(name):
            continue
        n = key[len(name):]
        if len(n) == 0 or n[0] != ' ':
            continue
        try:
            index, field = n[1:].split('-')
        except ValueError:
            continue
        if field == 'delete':
            delete.append(int(index))
        elif field == 'name':
            change[int(index)] = val

    if len(delete) == 0 and len(change) == 0:
        return None

    value = old_value

    # remove unwanted changes
    for i in delete:
        if i in change:
            del change[i]

    # perform requested changes
    for index, val in change.iteritems():
        val_list = val.split('/')
        stripped = list()
        for v in val_list:
            stripped.append(v.strip())
        if len(stripped) == 1:
            stripped = stripped[0]
        if len(value) <= index:
            value.extend([None]*(index + 1 - len(value)))
        value[index] = stripped

        if len(value[index]) == 0:
            value[index] = None

    # the previous loop may add 'None' entries
    # if any still exists mark them to be deleted
    for i in xrange(0, len(value)):
        if value[i] is None:
            delete.append(i)

    # remove duplicates and set in reverse order
    delete = list(set(delete))
    delete.sort(reverse=True)

    for i in delete:
        if len(value) > i:
            del value[i]

    if len(value) == 0:
        value = None
    return value


def get_mapping_list_value(name, old_value, **kwargs):
    delete = list()
    change = dict()
    for key, val in kwargs.iteritems():
        if not key.startswith(name):
            continue
        n = key[len(name):]
        if len(n) == 0 or n[0] != ' ':
            continue
        try:
            index, field = n[1:].split('-')
        except ValueError:
            continue
        if field == 'delete':
            delete.append(int(index))
        else:
            i = int(index)
            if i not in change:
                change[i] = dict()
            change[i][field] = val

    if len(delete) == 0 and len(change) == 0:
        return None

    value = old_value

    # remove unwanted changes
    for i in delete:
        if i in change:
            del change[i]

    # perform requested changes
    for index, fields in change.iteritems():
        for k in 'from', 'to':
            if k in fields:
                val = fields[k]
                val_list = val.split('/')
                stripped = list()
                for v in val_list:
                    stripped.append(v.strip())
                if len(stripped) == 1:
                    stripped = stripped[0]
                if len(value) <= index:
                    value.extend([None]*(index + 1 - len(value)))
                if value[index] is None:
                    value[index] = [None, None]
                if k == 'from':
                    i = 0
                else:
                    i = 1
                value[index][i] = stripped

        # eliminate incomplete/incorrect entries
        if value[index] is not None:
            if ((len(value[index]) != 2 or
                 value[index][0] is None or
                 len(value[index][0]) == 0 or
                 value[index][1] is None or
                 len(value[index][1]) == 0)):
                value[index] = None

    # the previous loop may add 'None' entries
    # if any still exists mark them to be deleted
    for i in xrange(0, len(value)):
        if value[i] is None:
            delete.append(i)

    # remove duplicates and set in reverse order
    delete = list(set(delete))
    delete.sort(reverse=True)

    for i in delete:
        if len(value) > i:
            del value[i]

    if len(value) == 0:
        value = None
    return value
