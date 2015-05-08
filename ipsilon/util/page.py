# Copyright (C) 2013 Ipsilon project Contributors, for license see COPYING

import cherrypy
from ipsilon.util.endpoint import Endpoint
from ipsilon.util.user import UserSession
from ipsilon.util.trans import Transaction
from urllib import unquote
try:
    from urlparse import urlparse
    from urlparse import parse_qs
except ImportError:
    # pylint: disable=no-name-in-module, import-error
    from urllib.parse import urlparse
    from urllib.parse import parse_qs


def admin_protect(fn):

    def check(*args, **kwargs):
        if UserSession().get_user().is_admin:
            return fn(*args, **kwargs)

        raise cherrypy.HTTPError(403)

    return check


class Page(Endpoint):
    def __init__(self, site, form=False):
        super(Page, self).__init__(site)
        if 'template_env' not in site:
            raise ValueError('Missing template environment')
        self._site = site
        self.basepath = cherrypy.config.get('base.mount', "")
        self.user = None
        self._is_form_page = form
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

        if len(args) > 0:
            op = getattr(self, args[0], None)
            if callable(op) and getattr(op, 'public_function', None):
                return op(*args[1:], **kwargs)
        else:
            if self._is_form_page:
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

    def _template_model(self):
        model = dict()
        model['basepath'] = self.basepath
        model['title'] = 'IPSILON'
        model['user'] = self.user
        return model

    def _template(self, *args, **kwargs):
        t = self._site['template_env'].get_template(args[0])
        m = self._template_model()
        m.update(kwargs)
        return t.render(**m)

    def default(self, *args, **kwargs):
        raise cherrypy.NotFound()

    def add_subtree(self, name, page):
        self.__dict__[name] = page

    def del_subtree(self, name):
        del self.__dict__[name]

    def get_valid_transaction(self, provider, **kwargs):
        try:
            t = Transaction(provider)
            # Try with kwargs first
            tid = t.find_tid(kwargs)
            if not tid:
                # If no TID yet See if we have it in a referer or in the
                # environment in the REDIRECT_URL
                url = None
                if 'referer' in cherrypy.request.headers:
                    url = cherrypy.request.headers['referer']
                    r = urlparse(unquote(url))
                    if r.query:
                        tid = t.find_tid(parse_qs(r.query))
                if not tid and 'REQUEST_URI' in cherrypy.request.wsgi_environ:
                    url = cherrypy.request.wsgi_environ['REQUEST_URI']
                    r = urlparse(unquote(url))
                    if r.query:
                        tid = t.find_tid(parse_qs(r.query))
                if not tid:
                    t.create_tid()
            return t
        except ValueError:
            msg = 'Transaction expired, or cookies not available'
            raise cherrypy.HTTPError(401, msg)

    exposed = True
