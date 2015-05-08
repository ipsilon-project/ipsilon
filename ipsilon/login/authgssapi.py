# Copyright (C) 2014 Ipsilon project Contributors, for license see COPYING

from ipsilon.login.common import LoginPageBase, LoginManagerBase, \
    LoginManagerInstaller
from ipsilon.util.plugin import PluginObject
from ipsilon.util.user import UserSession
from string import Template
import cherrypy
import os
import logging


class GSSAPI(LoginPageBase):

    def root(self, *args, **kwargs):
        # Someone typed manually or a robot is walking th tree.
        # Redirect to default page
        return self.lm.redirect_to_path(self.lm.path)


class GSSAPIAuth(LoginPageBase):

    def root(self, *args, **kwargs):
        trans = self.get_valid_transaction('login', **kwargs)
        # If we can get here, we must be authenticated and remote_user
        # was set. Check the session has a user set already or error.
        us = UserSession()
        us.remote_login()
        self.user = us.get_user()
        if not self.user.is_anonymous:
            principal = cherrypy.request.wsgi_environ.get('GSS_NAME', None)
            if principal:
                userdata = {'gssapi_principal_name': principal}
            else:
                userdata = {'gssapi_principal_name': self.user.name}
            return self.lm.auth_successful(trans, self.user.name,
                                           'gssapi', userdata)
        else:
            return self.lm.auth_failed(trans)


class GSSAPIError(LoginPageBase):

    def root(self, *args, **kwargs):
        cherrypy.log.error('REQUEST: %s' % cherrypy.request.headers,
                           severity=logging.DEBUG)
        # If we have no negotiate header return whatever mod_auth_gssapi
        # generated and wait for the next request

        if 'WWW-Authenticate' not in cherrypy.request.headers:
            cherrypy.response.status = 401

            next_login = self.lm.next_login()
            if next_login:
                return next_login.page.root(*args, **kwargs)

            conturl = '%s/login' % self.basepath
            return self._template('login/gssapi.html',
                                  title='GSSAPI Login',
                                  cont=conturl)

        # If we get here, negotiate failed
        trans = self.get_valid_transaction('login', **kwargs)
        return self.lm.auth_failed(trans)


class LoginManager(LoginManagerBase):

    def __init__(self, *args, **kwargs):
        super(LoginManager, self).__init__(*args, **kwargs)
        self.name = 'gssapi'
        self.path = 'gssapi/negotiate'
        self.page = None
        self.description = """
GSSAPI Negotiate authentication plugin. Relies on the mod_auth_gssapi
apache plugin for actual authentication. """
        self.new_config(self.name)

    def get_tree(self, site):
        self.page = GSSAPI(site, self)
        self.page.__dict__['negotiate'] = GSSAPIAuth(site, self)
        self.page.__dict__['unauthorized'] = GSSAPIError(site, self)
        self.page.__dict__['failed'] = GSSAPIError(site, self)
        return self.page


CONF_TEMPLATE = """

<Location /${instance}/login/gssapi/negotiate>
  AuthType GSSAPI
  AuthName "GSSAPI Single Sign On Login"
  $keytab
  GssapiSSLonly $gssapisslonly
  GssapiLocalName on
  Require valid-user

  ErrorDocument 401 /${instance}/login/gssapi/unauthorized
  ErrorDocument 500 /${instance}/login/gssapi/failed
</Location>
"""


class Installer(LoginManagerInstaller):

    def __init__(self, *pargs):
        super(Installer, self).__init__()
        self.name = 'gssapi'
        self.pargs = pargs

    def install_args(self, group):
        group.add_argument('--gssapi', choices=['yes', 'no'], default='no',
                           help='Configure GSSAPI authentication')
        group.add_argument('--gssapi-httpd-keytab',
                           default='/etc/httpd/conf/http.keytab',
                           help='Kerberos keytab location for HTTPD')

    def configure(self, opts, changes):
        if opts['gssapi'] != 'yes':
            return

        confopts = {'instance': opts['instance']}

        if os.path.exists(opts['gssapi_httpd_keytab']):
            confopts['keytab'] = 'GssapiCredStore keytab:%s' % (
                opts['gssapi_httpd_keytab'])
        else:
            raise Exception('Keytab not found')

        if opts['secure'] == 'no':
            confopts['gssapisslonly'] = 'Off'
        else:
            confopts['gssapisslonly'] = 'On'

        tmpl = Template(CONF_TEMPLATE)
        hunk = tmpl.substitute(**confopts)
        with open(opts['httpd_conf'], 'a') as httpd_conf:
            httpd_conf.write(hunk)

        # Add configuration data to database
        po = PluginObject(*self.pargs)
        po.name = 'gssapi'
        po.wipe_data()

        # Update global config, put 'gssapi' always first
        ph = self.pargs[0]
        ph.refresh_enabled()
        if 'gssapi' not in ph.enabled:
            enabled = []
            enabled.extend(ph.enabled)
            enabled.insert(0, 'gssapi')
            ph.save_enabled(enabled)
