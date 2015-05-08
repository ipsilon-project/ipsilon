# Copyright (C) 2014 Ipsilon project Contributors, for license see COPYING

from ipsilon.admin.common import AdminPlugins


FACILITY = 'login stack'


class LoginStackPlugins(AdminPlugins):

    def __init__(self, name, site, parent, facility, **kwargs):
        super(LoginStackPlugins, self).__init__(name, site, parent,
                                                facility,  **kwargs)
        self.parent = parent

    def root_with_msg(self, message=None, message_type=None, changed=None):
        return self.parent.root_with_msg(message, message_type, changed)


class LoginStack(AdminPlugins):
    def __init__(self, site, parent):
        self.children = []
        site[FACILITY] = None
        super(LoginStack, self).__init__('loginstack', site, parent, FACILITY)
        self.title = 'Login Stack'
        self.template = 'admin/loginstack.html'

    def add_subtree(self, name, page):
        self.__dict__[name] = page
        self.children.append(page)

    def del_subtree(self, name):
        self.children.remove(self.__dict__[name])
        del self.__dict__[name]

    def root_with_msg(self, message=None, message_type=None, changed=None):
        # Force the url to be that of the Login Stack
        kwargs = {'title': self.title,
                  'menu': self._master.menu,
                  'message': message,
                  'message_type': message_type,
                  'newurl': self.url,
                  'sections': list()}
        for child in self.children:
            # pylint: disable=protected-access
            plugins = child._site[child.facility]

            if changed is None:
                changed = dict()

            targs = {'title': child.title,
                     'available': plugins.available,
                     'enabled': plugins.enabled,
                     'changed': changed,
                     'baseurl': child.url}
            if child.order:
                targs['order_name'] = '%s_order_form' % child.name
                targs['order_action'] = child.order.url

            kwargs['sections'].append(targs)

        return self._template(self.template, **kwargs)
