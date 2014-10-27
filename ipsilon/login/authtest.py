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

from ipsilon.login.common import LoginFormBase, LoginManagerBase
from ipsilon.util.plugin import PluginObject
from ipsilon.util import config as pconfig
import cherrypy


class TestAuth(LoginFormBase):

    def POST(self, *args, **kwargs):
        username = kwargs.get("login_name")
        password = kwargs.get("login_password")
        error = None

        if username and password:
            if password == 'ipsilon':
                cherrypy.log("User %s successfully authenticated." % username)
                testdata = {'fullname': 'Test User %s' % username}
                return self.lm.auth_successful(self.trans,
                                               username, 'password', testdata)
            else:
                cherrypy.log("User %s failed authentication." % username)
                error = "Authentication failed"
        else:
            error = "Username or password is missing"
            cherrypy.log.error("Error: " + error)

        context = self.create_tmpl_context(
            username=username,
            error=error,
            error_password=not password,
            error_username=not username
        )
        # pylint: disable=star-args
        return self._template('login/form.html', **context)


class LoginManager(LoginManagerBase):

    def __init__(self, *args, **kwargs):
        super(LoginManager, self).__init__(*args, **kwargs)
        self.name = 'testauth'
        self.service_name = 'testauth'
        self.path = 'testauth'
        self.page = None
        self.description = """
Form based TEST login Manager, DO NOT EVER ACTIVATE IN PRODUCTION """
        self.new_config(
            self.name,
            pconfig.String(
                'username text',
                'Text used to ask for the username at login time.',
                'Username'),
            pconfig.String(
                'password text',
                'Text used to ask for the password at login time.',
                'Password'),
            pconfig.String(
                'help text',
                'Text used to guide the user at login time.',
                'DISABLE IN PRODUCTION, USE ONLY FOR TEST ' +
                'Use any username they are all valid, "admin" gives ' +
                'administrative powers. ' +
                'Use the fixed password "ipsilon" for any user')
        )

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
        self.page = TestAuth(site, self, 'login/testauth')
        return self.page


class Installer(object):

    def __init__(self, *pargs):
        self.name = 'testauth'
        self.ptype = 'login'
        self.pargs = pargs

    def install_args(self, group):
        group.add_argument('--testauth', choices=['yes', 'no'], default='no',
                           help='Configure PAM authentication')

    def configure(self, opts):
        if opts['testauth'] != 'yes':
            return

        print self.pargs
        # Add configuration data to database
        po = PluginObject(*self.pargs)
        po.name = 'testauth'
        po.wipe_data()

        # Update global config to add login plugin
        po.is_enabled = True
        po.save_enabled_state()
