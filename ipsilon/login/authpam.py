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

from ipsilon.login.common import LoginPageBase, LoginManagerBase
import cherrypy
import pam


class Pam(LoginPageBase):

    def _authenticate(self, username, password):
        if self.lm.service_name:
            ok = pam.authenticate(username, password, self.lm.service_name)
        else:
            ok = pam.authenticate(username, password)

        if ok:
            cherrypy.log("User %s successfully authenticated." % username)
            return username

        cherrypy.log("User %s failed authentication." % username)
        return None

    def GET(self, *args, **kwargs):
        return self._template('login/pam.html', title='Login',
                              action='%s/login/pam' % self.basepath,
                              service_name=self.lm.service_name,
                              help_text=self.lm.help_text,
                              username_text=self.lm.username_text,
                              password_text=self.lm.password_text)

    def POST(self, *args, **kwargs):
        username = None
        password = None
        user = None
        for key, value in kwargs.iteritems():
            if key == 'login_name':
                username = value
            elif key == 'login_password':
                password = value
        if username is not None and password is not None:
            user = self._authenticate(username, password)
        else:
            cherrypy.log.error("Error: Username or password is missing")

        if user:
            return self.lm.auth_successful(user)
        else:
            return self.lm.auth_failed()

    def root(self, *args, **kwargs):
        op = getattr(self, cherrypy.request.method, self.GET)
        if callable(op):
            return op(*args, **kwargs)


class LoginManager(LoginManagerBase):

    def __init__(self, *args, **kwargs):
        super(LoginManager, self).__init__(*args, **kwargs)
        self.name = 'pam'
        self.path = 'pam'
        self.page = None
        self.description = """
Form based login Manager that uses the system's PAM infrastructure
for authentication. """
        self._options = {
            'service name': [
                """ The name of the PAM service used to authenticate. """,
                'string',
                'remote'
            ],
            'help text': [
                """ The text shown to guide the user at login time. """,
                'string',
                'Insert your Username and Password and then submit.'
            ],
            'username text': [
                """ The text shown to ask for the username in the form. """,
                'string',
                'Username'
            ],
            'password text': [
                """ The text shown to ask for the password in the form. """,
                'string',
                'Password'
            ],
        }

    @property
    def service_name(self):
        return self.get_config_value('service name')

    @property
    def help_text(self):
        return self.get_config_value('help text')

    @property
    def username_text(self):
        return self.get_config_value('username text')

    @property
    def password_text(self):
        return self.get_config_value('password text')

    def get_tree(self, site):
        self.page = Pam(site, self)
        return self.page
