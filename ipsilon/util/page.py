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
import cherrypy


def admin_protect(fn):

    def check(*args, **kwargs):
        if UserSession().get_user().is_admin:
            return fn(*args, **kwargs)

        raise cherrypy.HTTPError(403)

    return check


def protect():
    UserSession().remote_login()


class Page(object):
    def __init__(self, site):
        if not 'template_env' in site:
            raise ValueError('Missing template environment')
        self._site = site
        self.basepath = cherrypy.config.get('base.mount', "")
        self.user = None

    def __call__(self, *args, **kwargs):
        # pylint: disable=star-args
        self.user = UserSession().get_user()

        if len(args) > 0:
            op = getattr(self, args[0], None)
            if callable(op) and getattr(self, args[0]+'.exposed', None):
                return op(*args[1:], **kwargs)
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
