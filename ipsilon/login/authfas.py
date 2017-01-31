# Copyright (C) 2014,2016 Ipsilon project Contributors, for license see COPYING

from ipsilon.login.common import LoginFormBase, LoginManagerBase, \
    LoginManagerInstaller
from ipsilon.info.infofas import fas_make_userdata
from ipsilon.util.plugin import PluginObject
from ipsilon.util import config as pconfig
import cherrypy
import logging

from fedora.client.fasproxy import FasProxyClient
from fedora.client import AuthError


class FAS(LoginFormBase):

    def __init__(self, site, mgr, page):
        super(FAS, self).__init__(site, mgr, page)

    def POST(self, *args, **kwargs):
        username = kwargs.get("login_name")
        password = kwargs.get("login_password")
        error = None

        if username and password:
            data = None
            try:
                _, data = self.lm.fpc.login(username, password)
            except AuthError, e:
                cherrypy.log.error("Authentication error [%s]" % str(e),
                                   severity=logging.ERROR)
            except Exception, e:  # pylint: disable=broad-except
                cherrypy.log.error("Unknown Error [%s]" % str(e),
                                   severity=logging.ERROR)

            if data and data.user:
                userdata = fas_make_userdata(data.user)
                return self.lm.auth_successful(self.trans,
                                               data.user['username'],
                                               userdata=userdata)
            else:
                error = "Authentication failed"
                cherrypy.log.error(error, severity=logging.ERROR)
        else:
            error = "Username or password is missing"
            cherrypy.log.error("Error: " + error, severity=logging.ERROR)

        context = self.create_tmpl_context(
            username=username,
            error=error,
            error_password=not password,
            error_username=not username
        )
        self.lm.set_auth_error()
        return self._template(self.formtemplate, **context)


class LoginManager(LoginManagerBase):

    def __init__(self, *args, **kwargs):
        super(LoginManager, self).__init__(*args, **kwargs)
        self.name = 'fas'
        self.path = 'fas'
        self.service_name = 'fas'
        self.page = None
        self.fpc = None
        self.description = """
Form based login Manager that uses the Fedora Authentication Server
"""
        self.new_config(
            self.name,
            pconfig.String(
                'FAS url',
                'The FAS Url.',
                'https://admin.fedoraproject.org/accounts/'),
            pconfig.String(
                'FAS Proxy client user Agent',
                'The User Agent presented to the FAS Server.',
                'Ipsilon v1.0'),
            pconfig.Condition(
                'FAS Insecure Auth',
                'If checked skips FAS server cert verification.',
                False),
            pconfig.String(
                'username text',
                'Text used to ask for the username at login time.',
                'FAS Username'),
            pconfig.String(
                'password text',
                'Text used to ask for the password at login time.',
                'Password'),
            pconfig.String(
                'help text',
                'Text used to guide the user at login time.',
                'Login with your FAS credentials')
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

    @property
    def fas_url(self):
        return self.get_config_value('FAS url')

    @property
    def user_agent(self):
        return self.get_config_value('FAS Proxy client user Agent')

    @property
    def insecure(self):
        return self.get_config_value('FAS Insecure Auth')

    def get_tree(self, site):
        self.page = FAS(site, self, 'login/fas')
        return self.page

    def on_enable(self):
        super(LoginManager, self).on_enable()
        self.fpc = FasProxyClient(base_url=self.fas_url,
                                  useragent=self.user_agent,
                                  insecure=self.insecure)


class Installer(LoginManagerInstaller):

    def __init__(self, *pargs):
        super(Installer, self).__init__()
        self.name = 'fas'
        self.pargs = pargs

    def install_args(self, group):
        group.add_argument('--fas', choices=['yes', 'no'], default='no',
                           help='Configure FAS authentication')

    def configure(self, opts, changes):
        if opts['fas'] != 'yes':
            return

        # Add configuration data to database
        po = PluginObject(*self.pargs)
        po.name = 'fas'
        po.wipe_data()
        po.wipe_config_values()

        # Update global config to add login plugin
        po.is_enabled = True
        po.save_enabled_state()
