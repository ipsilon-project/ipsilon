# Copyright (C) 2015 Ipsilon project Contributors, for license see COPYING

import cherrypy
import json
import logging
from functools import wraps
from ipsilon.util.endpoint import Endpoint


def jsonout(func):
    """
    JSON output decorator. Does not handle binary data.
    """
    @wraps(func)
    def wrapper(*args, **kw):
        value = func(*args, **kw)
        cherrypy.response.headers["Content-Type"] = \
            "application/json;charset=utf-8"
        return json.dumps(value, sort_keys=True, indent=2)

    return wrapper


def rest_error(status=500, message=''):
    """
    Create a REST error response.

    The assumption is that the jsonout wrapper will handle converting
    the response to JSON.
    """
    cherrypy.response.status = status
    cherrypy.response.headers['Content-Type'] = 'application/json'
    return {'status': status, 'message': message}


class RestPage(Endpoint):

    def __init__(self, *args, **kwargs):
        super(RestPage, self).__init__(*args, **kwargs)
        self.auth_protect = True


class RestPlugins(RestPage):
    def __init__(self, name, site, parent, facility, ordered=True):
        super(RestPlugins, self).__init__(site)
        self._master = parent
        self.name = name
        self.title = '%s plugins' % name
        self.url = '%s/%s' % (parent.url, name)
        self.facility = facility
        self.template = None
        self.order = None
        parent.add_subtree(name, self)

        for plugin in self._site[facility].available:
            obj = self._site[facility].available[plugin]
            if hasattr(obj, 'rest'):
                cherrypy.log.error('Rest plugin: %s' % plugin,
                                   severity=logging.DEBUG)
                obj.rest.mount(self)

    def root_with_msg(self, message=None, message_type=None, changed=None):
        return None

    def root(self, *args, **kwargs):
        return self.root_with_msg()


class Rest(RestPage):

    def __init__(self, site, mount):
        super(Rest, self).__init__(site)
        self.title = None
        self.mount = mount
        self.url = '%s/%s' % (self.basepath, mount)
        self.menu = [self]

    @jsonout
    def root(self, *args, **kwargs):
        return rest_error(404, 'Not Found')

    def add_subtree(self, name, page):
        self.__dict__[name] = page

    def del_subtree(self, name):
        del self.__dict__[name]
