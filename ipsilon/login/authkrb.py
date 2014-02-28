#!/usr/bin/python
#
# Copyright (C) 2014  Simo Sorce <simo@redhat.com>
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

from ipsilon.login.common import LoginPageBase, LoginManagerBase
from ipsilon.util.user import UserSession
import cherrypy


class Krb(LoginPageBase):

    def root(self, *args, **kwargs):
        # Someone typed manually or a robot is walking th tree.
        # Redirect to default page
        return self.lm.redirect_to_path(self.lm.path)


class KrbAuth(LoginPageBase):

    def root(self, *args, **kwargs):
        # If we can get here, we must be authenticated and remote_user
        # was set. Check the session has a user set already or error.
        if self.user and self.user.name:
            userdata = { 'krb_principal_name': self.user.name }
            return self.lm.auth_successful(self.user.name, userdata)
        else:
            return self.lm.auth_failed()


class KrbError(LoginPageBase):

    def root(self, *args, **kwargs):
        cherrypy.log.error('REQUEST: %s' % cherrypy.request.headers)
        # If we have no negotiate header return whatever mod_auth_kerb
        # generated and wait for the next request

        if not 'WWW-Authenticate' in cherrypy.request.headers:
            cherrypy.response.status = 401

            if self.lm.next_login:
                return self.lm.next_login.page.root(*args, **kwargs)

            conturl = '%s/login' % self.basepath
            return self._template('login/krb.html',
                                  title='Kerberos Login',
                                  cont=conturl)

        # If we get here, negotiate failed
        return self.lm.auth_failed()


class LoginManager(LoginManagerBase):

    def __init__(self, *args, **kwargs):
        super(LoginManager, self).__init__(*args, **kwargs)
        self.name = 'krb'
        self.path = 'krb/negotiate'
        self.page = None
        self.description = """
Kereros Negotiate authentication plugin. Relies on the mod_auth_kerb apache
plugin for actual authentication. """

    def get_tree(self, site):
        self.page = Krb(site, self)
        self.page.__dict__['negotiate'] = KrbAuth(site, self)
        self.page.__dict__['unauthorized'] = KrbError(site, self)
        return self.page
