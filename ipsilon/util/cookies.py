# Copyright (C) 2014 Ipsilon project Contributors, for license see COPYING

from ipsilon.util.log import Log
import cherrypy
import uuid


class SecureCookie(Log):

    def __init__(self, name=None, value=None, maxage=None, expires=None):
        if name is None:
            self.name = str(uuid.uuid4())
        else:
            self.name = str(name)
        self.path = None
        self.secure = cherrypy.config.get('tools.sessions.secure', True)
        self.httponly = cherrypy.config.get('tools.sessions.httponly', True)
        self.maxage = maxage
        self.expires = expires
        self.value = value

    def _get_cookie_attr(self, name):
        return getattr(cherrypy.request.cookie[self.name], name, None)

    def _set_cookie_attr(self, name, value):
        if value is not None and value is not False:
            cherrypy.response.cookie[self.name][name] = value

    def receive(self):
        if self.name not in cherrypy.request.cookie:
            return

        self.value = cherrypy.request.cookie[self.name].value
        self.path = self._get_cookie_attr('path')
        self.secure = self._get_cookie_attr('secure')
        self.httponly = self._get_cookie_attr('httponly')
        self.maxage = self._get_cookie_attr('max-age')
        self.expires = self._get_cookie_attr('expires')

    def _store(self):
        if self.value is None:
            raise ValueError('Cookie has no value')
        if self.maxage is None and self.expires is not 0:
            # 5 minutes should be enough ...
            self.maxage = 300
        cherrypy.response.cookie[self.name] = str(self.value)
        if self.path:
            path = self.path
        else:
            path = cherrypy.config.get('base.mount', '/')
        self._set_cookie_attr('path', path)
        self._set_cookie_attr('secure', self.secure)
        self._set_cookie_attr('httponly', self.httponly)
        self._set_cookie_attr('max-age', self.maxage)
        self._set_cookie_attr('expires', self.expires)
        self.debug('Cookie op: %s' % cherrypy.response.cookie[self.name])

    def delete(self):
        self.expires = 0
        self.debug('Deleting cookie %s' % self.name)
        self._store()

    def send(self):
        self.debug('Sending cookie %s' % self.name)
        self._store()
