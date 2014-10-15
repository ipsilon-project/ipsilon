#!/usr/bin/python
#
# Copyright (C) 2013  Simo Sorce <simo@redhat.com>
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
from ipsilon.util.log import Log
from ipsilon.util.user import UserSession
from ipsilon.util.trans import Transaction
from urllib import unquote
try:
    from urlparse import urlparse
except ImportError:
    # pylint: disable=no-name-in-module, import-error
    from urllib.parse import urlparse


def admin_protect(fn):

    def check(*args, **kwargs):
        if UserSession().get_user().is_admin:
            return fn(*args, **kwargs)

        raise cherrypy.HTTPError(403)

    return check


class Page(Log):
    def __init__(self, site, form=False):
        if 'template_env' not in site:
            raise ValueError('Missing template environment')
        self._site = site
        self.basepath = cherrypy.config.get('base.mount', "")
        self.user = None
        self._is_form_page = form
        self.default_headers = dict()
        self.auth_protect = False

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
        # pylint: disable=star-args
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
                self._debug("method: %s" % cherrypy.request.method)
                op = getattr(self, cherrypy.request.method, None)
                if callable(op):
                    # Basic CSRF protection
                    if cherrypy.request.method != 'GET':
                        url = cherrypy.url(relative=False)
                        if 'referer' not in cherrypy.request.headers:
                            self._debug("Missing referer in %s request to %s"
                                        % (cherrypy.request.method, url))
                            raise cherrypy.HTTPError(403)
                        referer = cherrypy.request.headers['referer']
                        if not self._check_referer(referer, url):
                            self._debug("Wrong referer %s in request to %s"
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
        # pylint: disable=star-args
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
            return Transaction(provider, **kwargs)
        except ValueError:
            msg = 'Transaction expired, or cookies not available'
            raise cherrypy.HTTPError(401, msg)

    exposed = True
