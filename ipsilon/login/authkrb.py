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
from ipsilon.login.common import FACILITY
from ipsilon.util.plugin import PluginObject
from string import Template
import cherrypy
import os


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
            userdata = {'krb_principal_name': self.user.name}
            return self.lm.auth_successful(self.user.name, userdata)
        else:
            return self.lm.auth_failed()


class KrbError(LoginPageBase):

    def root(self, *args, **kwargs):
        cherrypy.log.error('REQUEST: %s' % cherrypy.request.headers)
        # If we have no negotiate header return whatever mod_auth_kerb
        # generated and wait for the next request

        if 'WWW-Authenticate' not in cherrypy.request.headers:
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
        self.page.__dict__['failed'] = KrbError(site, self)
        return self.page


CONF_TEMPLATE = """

<Location /${instance}/login/krb/negotiate>
  AuthType Kerberos
  AuthName "Kerberos Login"
  KrbMethodNegotiate on
  KrbMethodK5Passwd off
  KrbServiceName HTTP
  $realms
  $keytab
  KrbSaveCredentials off
  KrbConstrainedDelegation off
  # KrbLocalUserMapping On
  Require valid-user

  ErrorDocument 401 /${instance}/login/krb/unauthorized
  ErrorDocument 500 /${instance}/login/krb/failed
</Location>
"""


class Installer(object):

    def __init__(self):
        self.name = 'krb'
        self.ptype = 'login'

    def install_args(self, group):
        group.add_argument('--krb', choices=['yes', 'no'], default='no',
                           help='Configure Kerberos authentication')
        group.add_argument('--krb-realms',
                           help='Allowed Kerberos Auth Realms')
        group.add_argument('--krb-httpd-keytab',
                           default='/etc/httpd/conf/http.keytab',
                           help='Kerberos keytab location for HTTPD')

    def configure(self, opts):
        if opts['krb'] != 'yes':
            return

        confopts = {'instance': opts['instance']}

        if os.path.exists(opts['krb_httpd_keytab']):
            confopts['keytab'] = '  Krb5KeyTab %s' % opts['krb_httpd_keytab']
        else:
            raise Exception('Keytab not found')

        if opts['krb_realms'] is None:
            confopts['realms'] = '  # KrbAuthRealms - Any realm is allowed'
        else:
            confopts['realms'] = '  KrbAuthRealms %s' % opts['krb_realms']

        tmpl = Template(CONF_TEMPLATE)
        hunk = tmpl.substitute(**confopts)  # pylint: disable=star-args
        with open(opts['httpd_conf'], 'a') as httpd_conf:
            httpd_conf.write(hunk)

        # Add configuration data to database
        po = PluginObject()
        po.name = 'krb'
        po.wipe_data()

        # Update global config, put 'krb' always first
        po.name = 'global'
        globalconf = po.get_plugin_config(FACILITY)
        if 'order' in globalconf:
            order = globalconf['order'].split(',')
        else:
            order = []
        order.insert(0, 'krb')
        globalconf['order'] = ','.join(order)
        po.set_config(globalconf)
        po.save_plugin_config(FACILITY)
