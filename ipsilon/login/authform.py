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
from ipsilon.login.common import FACILITY
from ipsilon.util.plugin import PluginObject
from ipsilon.util.user import UserSession
from string import Template
import cherrypy
import subprocess


class Form(LoginFormBase):

    def POST(self, *args, **kwargs):
        us = UserSession()
        us.remote_login()
        user = us.get_user()
        if not user.is_anonymous:
            return self.lm.auth_successful(user.name, 'password')
        else:
            try:
                error = cherrypy.request.headers['EXTERNAL_AUTH_ERROR']
            except KeyError:
                error = "Unknown error using external authentication"
                cherrypy.log.error("Error: %s" % error)
            return self.lm.auth_failed()


class LoginManager(LoginManagerBase):

    def __init__(self, *args, **kwargs):
        super(LoginManager, self).__init__(*args, **kwargs)
        self.name = 'form'
        self.path = 'form'
        self.page = None
        self.description = """
Form based login Manager. Relies on mod_intercept_form_submit plugin for
 actual authentication. """
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
        self.page = Form(site, self, 'login/form')
        return self.page


CONF_TEMPLATE = """
LoadModule intercept_form_submit_module modules/mod_intercept_form_submit.so
LoadModule authnz_pam_module modules/mod_authnz_pam.so

<Location /${instance}/login/form>
  InterceptFormPAMService ${service}
  InterceptFormLogin login_name
  InterceptFormPassword login_password
  # InterceptFormLoginSkip admin
  # InterceptFormClearRemoteUserForSkipped on
  InterceptFormPasswordRedact on
</Location>
"""


class Installer(object):

    def __init__(self):
        self.name = 'form'
        self.ptype = 'login'

    def install_args(self, group):
        group.add_argument('--form', choices=['yes', 'no'], default='no',
                           help='Configure External Form authentication')
        group.add_argument('--form-service', action='store', default='remote',
                           help='PAM service name to use for authentication')

    def configure(self, opts):
        if opts['form'] != 'yes':
            return

        confopts = {'instance': opts['instance'],
                    'service': opts['form_service']}

        tmpl = Template(CONF_TEMPLATE)
        hunk = tmpl.substitute(**confopts)  # pylint: disable=star-args
        with open(opts['httpd_conf'], 'a') as httpd_conf:
            httpd_conf.write(hunk)

        # Add configuration data to database
        po = PluginObject()
        po.name = 'form'
        po.wipe_data()
        po.wipe_config_values(FACILITY)

        # Update global config, put 'krb' always first
        po.name = 'global'
        globalconf = po.get_plugin_config(FACILITY)
        if 'order' in globalconf:
            order = globalconf['order'].split(',')
        else:
            order = []
        order.append('form')
        globalconf['order'] = ','.join(order)
        po.set_config(globalconf)
        po.save_plugin_config(FACILITY)

        # for selinux enabled platforms, ignore if it fails just report
        try:
            subprocess.call(['/usr/sbin/setsebool', '-P',
                             'httpd_mod_auth_pam=on'])
        except Exception:  # pylint: disable=broad-except
            pass
