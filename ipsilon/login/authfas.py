#!/usr/bin/python
#
# Copyright (C) 2014 Ipsilon contributors, see COPYING file for license


from ipsilon.login.common import LoginPageBase, LoginManagerBase
from ipsilon.login.common import FACILITY
from ipsilon.util.plugin import PluginObject
import cherrypy

from fedora.client.fasproxy import FasProxyClient
from fedora.client import AuthError


class FAS(LoginPageBase):

    def GET(self, *args, **kwargs):
        context = self.create_tmpl_context()
        # pylint: disable=star-args
        return self._template('login/fas.html', **context)

    def POST(self, *args, **kwargs):
        username = kwargs.get("login_name")
        password = kwargs.get("login_password")
        error = None

        if username and password:
            data = None
            try:
                _, data = self.lm.fpc.login(username, password)
            except AuthError, e:
                cherrypy.log.error("Authentication error [%s]" % str(e))
            except Exception, e:  # pylint: disable=broad-except
                cherrypy.log.error("Unknown Error [%s]" % str(e))
            if data and data.user:
                return self.lm.auth_successful(data.user['username'],
                                               userdata={'fas': data.user})
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
        return self._template('login/fas.html', **context)

    def root(self, *args, **kwargs):
        op = getattr(self, cherrypy.request.method, self.GET)
        if callable(op):
            return op(*args, **kwargs)

    def create_tmpl_context(self, **kwargs):
        next_url = None
        if self.lm.next_login is not None:
            next_url = self.lm.next_login.path

        context = {
            "title": 'Login',
            "action": '%s/login/fas' % self.basepath,
            "username_text": self.lm.username_text,
            "password_text": self.lm.password_text,
            "description": self.lm.help_text,
            "next_url": next_url,
        }
        context.update(kwargs)
        return context


class LoginManager(LoginManagerBase):

    def __init__(self, *args, **kwargs):
        super(LoginManager, self).__init__(*args, **kwargs)
        self.name = 'fas'
        self.path = 'fas'
        self.page = None
        self.fpc = None
        self.description = """
Form based login Manager that uses the Fedora Authentication Server
"""
        self._options = {
            'help text': [
                """ The text shown to guide the user at login time. """,
                'string',
                'Login wth your FAS credentials'
            ],
            'username text': [
                """ The text shown to ask for the username in the form. """,
                'string',
                'FAS Username'
            ],
            'password text': [
                """ The text shown to ask for the password in the form. """,
                'string',
                'Password'
            ],
            'FAS url': [
                """ The FAS Url. """,
                'string',
                'https://admin.fedoraproject.org/accounts/'
            ],
            'FAS Proxy client user Agent': [
                """ The User Agent presented to the FAS Server. """,
                'string',
                'Ipsilon v1.0'
            ],
            'FAS Insecure Auth': [
                """ If 'YES' skips FAS server cert verification. """,
                'string',
                ''
            ],
        }

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
        self.fpc = FasProxyClient(base_url=self.fas_url,
                                  useragent=self.user_agent,
                                  insecure=(self.insecure == 'YES'))
        self.page = FAS(site, self)
        return self.page


class Installer(object):

    def __init__(self):
        self.name = 'fas'
        self.ptype = 'login'

    def install_args(self, group):
        group.add_argument('--fas', choices=['yes', 'no'], default='no',
                           help='Configure FAS authentication')

    def configure(self, opts):
        if opts['fas'] != 'yes':
            return

        # Add configuration data to database
        po = PluginObject()
        po.name = 'fas'
        po.wipe_data()

        po.wipe_config_values(FACILITY)

        # Update global config to add login plugin
        po = PluginObject()
        po.name = 'global'
        globalconf = po.get_plugin_config(FACILITY)
        if 'order' in globalconf:
            order = globalconf['order'].split(',')
        else:
            order = []
        order.append('fas')
        globalconf['order'] = ','.join(order)
        po.set_config(globalconf)
        po.save_plugin_config(FACILITY)
