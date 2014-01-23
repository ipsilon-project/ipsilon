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

from ipsilon.util.user import User
import cherrypy

def protect():
    if cherrypy.request.login:
        user = cherrypy.session.get('user', None)
        if user == cherrypy.request.login:
            return
        else:
            cherrypy.session.regenerate()
            cherrypy.session['user'] = cherrypy.request.login

class Page(object):
    def __init__(self, template_env):
        self._env = template_env
        self.basepath = cherrypy.config.get('base.mount', "")
        self.username = None
        self.user = None

    def __call__(self, *args, **kwargs):
        # pylint: disable=star-args
        self.username = cherrypy.session.get('user', None)
        self.user = User(self.username)

        if len(args) > 0:
            op = getattr(self, args[0], None)
            if callable(op) and getattr(self, args[0]+'.exposed', None):
                return op(args[1:], **kwargs)
        else:
            op = getattr(self, 'root', None)
            if callable(op):
                return op(**kwargs)

        return self.default(*args, **kwargs)

    def _template(self, *args, **kwargs):
        t = self._env.get_template(args[0])
        return t.render(basepath=self.basepath, user=self.user, **kwargs)

    def default(self, *args, **kwargs):
        raise cherrypy.HTTPError(404)

    exposed = True
