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

from ipsilon.login.common import LoginFormBase, LoginManagerBase
from ipsilon.login.common import FACILITY
from ipsilon.util.plugin import PluginObject
import cherrypy
import pam
import subprocess


class Pam(LoginFormBase):

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

    def POST(self, *args, **kwargs):
        username = kwargs.get("login_name")
        password = kwargs.get("login_password")
        user = None
        error = None

        if username and password:
            user = self._authenticate(username, password)
            if user:
                return self.lm.auth_successful(user)
            else:
                error = "Authentication failed"
                cherrypy.log.error(error)
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
        self.page = Pam(site, self, 'login/pam')
        return self.page


class Installer(object):

    def __init__(self):
        self.name = 'pam'
        self.ptype = 'login'

    def install_args(self, group):
        group.add_argument('--pam', choices=['yes', 'no'], default='no',
                           help='Configure PAM authentication')
        group.add_argument('--pam-service', action='store', default='remote',
                           help='PAM service name to use for authentication')

    def configure(self, opts):
        if opts['pam'] != 'yes':
            return

        # Add configuration data to database
        po = PluginObject()
        po.name = 'pam'
        po.wipe_data()

        po.wipe_config_values(FACILITY)
        config = {'service name': opts['pam_service']}
        po.set_config(config)
        po.save_plugin_config(FACILITY)

        # Update global config to add login plugin
        po = PluginObject()
        po.name = 'global'
        globalconf = po.get_plugin_config(FACILITY)
        if 'order' in globalconf:
            order = globalconf['order'].split(',')
        else:
            order = []
        order.append('pam')
        globalconf['order'] = ','.join(order)
        po.set_config(globalconf)
        po.save_plugin_config(FACILITY)

        # for selinux enabled platforms, ignore if it fails just report
        try:
            subprocess.call(['/usr/sbin/setsebool', '-P',
                             'httpd_mod_auth_pam=on',
                             'httpd_tmp_exec=on'])
        except Exception:  # pylint: disable=broad-except
            pass
