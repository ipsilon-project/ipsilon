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

from ipsilon.util.user import UserSession
from urllib import unquote
import cherrypy


def admin_protect(fn):

    def check(*args, **kwargs):
        if UserSession().get_user().is_admin:
            return fn(*args, **kwargs)

        raise cherrypy.HTTPError(403)

    return check


class Page(object):
    def __init__(self, site, form=False):
        if 'template_env' not in site:
            raise ValueError('Missing template environment')
        self._site = site
        self.basepath = cherrypy.config.get('base.mount', "")
        self.user = None
        self.form = form

    def _compare_urls(self, url1, url2):
        u1 = unquote(url1)
        u2 = unquote(url2)
        if u1 == u2:
            return True
        return False

    def __call__(self, *args, **kwargs):
        # pylint: disable=star-args
        self.user = UserSession().get_user()

        if len(args) > 0:
            op = getattr(self, args[0], None)
            if callable(op) and getattr(self, args[0]+'.exposed', None):
                return op(*args[1:], **kwargs)
        else:
            if self.form:
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
                        if not self._compare_urls(referer, url):
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

    def _debug(self, fact):
        if cherrypy.config.get('debug', False):
            cherrypy.log(fact)

    def default(self, *args, **kwargs):
        raise cherrypy.HTTPError(404)

    def add_subtree(self, name, page):
        self.__dict__[name] = page

    def del_subtree(self, name):
        del self.__dict__[name]

    exposed = True
