# Copyright (C) 2015 Ipsilon project Contributors, for license see COPYING

import cherrypy
from ipsilon.util.log import Log
from ipsilon.util.user import UserSession
from urllib import unquote
from functools import wraps
try:
    from urlparse import urlparse
except ImportError:
    # pylint: disable=no-name-in-module, import-error
    from urllib.parse import urlparse


def allow_iframe(func):
    """
    Remove the X-Frame-Options and CSP frame-options deny headers.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        for (header, value) in [
                ('X-Frame-Options', 'deny'),
                ('Content-Security-Policy', 'frame-options \'deny\'')]:
            if cherrypy.response.headers.get(header, None) == value:
                cherrypy.response.headers.pop(header, None)
        return result

    return wrapper


class Endpoint(Log):
    def __init__(self, site):
        self._site = site
        self.basepath = cherrypy.config.get('base.mount', "")
        self.user = None
        self.default_headers = {
            'Cache-Control': 'no-cache, no-store, must-revalidate, private',
            'Pragma': 'no-cache',
            'Content-Security-Policy': 'frame-options \'deny\'',
            'X-Frame-Options': 'deny',
        }
        self.auth_protect = False

    def get_url(self):
        return cherrypy.url(relative=False)

    def instance_base_url(self):
        url = self.get_url()
        s = urlparse(unquote(url))
        return '%s://%s%s' % (s.scheme, s.netloc, self.basepath)

    def _check_referer(self, referer, url):
        r = urlparse(unquote(referer))
        u = urlparse(unquote(url))
        if r.scheme != u.scheme:
            return False
        if r.netloc != u.netloc:
            return False
        if r.path.startswith(self.basepath):
            return True
        return False

    def __call__(self, *args, **kwargs):
        cherrypy.response.headers.update(self.default_headers)

        self.user = UserSession().get_user()

        if self.auth_protect and self.user.is_anonymous:
            raise cherrypy.HTTPError(401)

        self.debug("method: %s" % cherrypy.request.method)
        op = getattr(self, cherrypy.request.method, None)
        if callable(op):
            # Basic CSRF protection
            if cherrypy.request.method != 'GET':
                url = self.get_url()
                if 'referer' not in cherrypy.request.headers:
                    self.debug("Missing referer in %s request to %s"
                               % (cherrypy.request.method, url))
                    raise cherrypy.HTTPError(403)
                referer = cherrypy.request.headers['referer']
                if not self._check_referer(referer, url):
                    self.debug("Wrong referer %s in request to %s"
                               % (referer, url))
                    raise cherrypy.HTTPError(403)
            return op(*args, **kwargs)
        else:
            op = getattr(self, 'root', None)
            if callable(op):
                return op(*args, **kwargs)

        return self.default(*args, **kwargs)

    def default(self, *args, **kwargs):
        raise cherrypy.NotFound()

    def add_subtree(self, name, page):
        self.__dict__[name] = page

    def del_subtree(self, name):
        del self.__dict__[name]

    exposed = True
