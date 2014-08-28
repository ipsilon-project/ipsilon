#!/usr/bin/python
#
# Copyright (C) 2014  Ipsilon Contributors, see COPYING for license

from ipsilon.login.common import LoginFormBase, LoginManagerBase
from ipsilon.login.common import FACILITY
from ipsilon.util.plugin import PluginObject
from ipsilon.util.log import Log
from ipsilon.info.infoldap import InfoProvider as LDAPInfo
import ldap


class LDAP(LoginFormBase, Log):

    def __init__(self, site, mgr, page):
        super(LDAP, self).__init__(site, mgr, page)
        self.ldap_info = None

    def _ldap_connect(self):

        tls = self.lm.tls.lower()
        tls_req_opt = None
        if tls == "never":
            tls_req_opt = ldap.OPT_X_TLS_NEVER
        elif tls == "demand":
            tls_req_opt = ldap.OPT_X_TLS_DEMAND
        elif tls == "allow":
            tls_req_opt = ldap.OPT_X_TLS_ALLOW
        elif tls == "try":
            tls_req_opt = ldap.OPT_X_TLS_TRY
        if tls_req_opt is not None:
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, tls_req_opt)

        conn = ldap.initialize(self.lm.server_url)

        if tls != "notls":
            if not self.lm.server_url.startswith("ldaps"):
                conn.start_tls_s()
        return conn

    def _authenticate(self, username, password):

        conn = self._ldap_connect()
        dn = self.lm.bind_dn_tmpl % {'username': username}
        conn.simple_bind_s(dn, password)

        # Bypass info plugins to optimize data retrieval
        if self.lm.get_user_info:
            self.lm.info = None

            if not self.ldap_info:
                self.ldap_info = LDAPInfo()

            return self.ldap_info.get_user_data_from_conn(conn, dn)

        return None

    def POST(self, *args, **kwargs):
        username = kwargs.get("login_name")
        password = kwargs.get("login_password")
        userattrs = None
        authed = False
        errmsg = None

        if username and password:
            try:
                userattrs = self._authenticate(username, password)
                authed = True
            except Exception, e:  # pylint: disable=broad-except
                errmsg = "Authentication failed"
                self.error("Exception raised: [%s]" % repr(e))
        else:
            errmsg = "Username or password is missing"
            self.error(errmsg)

        if authed:
            return self.lm.auth_successful(self.trans, username, 'password',
                                           userdata=userattrs)

        context = self.create_tmpl_context(
            username=username,
            error=errmsg,
            error_password=not password,
            error_username=not username
        )
        # pylint: disable=star-args
        return self._template('login/form.html', **context)


class LoginManager(LoginManagerBase):

    def __init__(self, *args, **kwargs):
        super(LoginManager, self).__init__(*args, **kwargs)
        self.name = 'ldap'
        self.path = 'ldap'
        self.page = None
        self.ldap_info = None
        self.service_name = 'ldap'
        self.description = """
Form based login Manager that uses a simple bind LDAP operation to perform
authentication. """
        self._options = {
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
            'server url': [
                """ The LDAP server url """,
                'string',
                'ldap://example.com'
            ],
            'tls': [
                " What TLS level show be required " +
                "(Demand, Allow, Try, Never, NoTLS) ",
                'string',
                'Demand'
            ],
            'bind dn template': [
                """ Template to turn username into DN. """,
                'string',
                'uid=%(username)s,ou=People,dc=example,dc=com'
            ],
            'get user info': [
                """ Get user info via ldap directly after auth (Yes/No) """,
                'string',
                'Yes'
            ],
        }
        self.conf_opt_order = ['server url', 'bind dn template',
                               'get user info', 'tls', 'username text',
                               'password text', 'help text']

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
    def server_url(self):
        return self.get_config_value('server url')

    @property
    def tls(self):
        return self.get_config_value('tls')

    @property
    def get_user_info(self):
        return (self.get_config_value('get user info').lower() == 'yes')

    @property
    def bind_dn_tmpl(self):
        return self.get_config_value('bind dn template')

    def get_tree(self, site):
        self.page = LDAP(site, self, 'login/ldap')
        return self.page


class Installer(object):

    def __init__(self):
        self.name = 'ldap'
        self.ptype = 'login'

    def install_args(self, group):
        group.add_argument('--ldap', choices=['yes', 'no'], default='no',
                           help='Configure PAM authentication')
        group.add_argument('--ldap-server-url', action='store',
                           help='LDAP Server Url')
        group.add_argument('--ldap-bind-dn-template', action='store',
                           help='LDAP Bind DN Template')

    def configure(self, opts):
        if opts['ldap'] != 'yes':
            return

        # Add configuration data to database
        po = PluginObject()
        po.name = 'ldap'
        po.wipe_data()

        po.wipe_config_values(FACILITY)
        config = dict()
        if 'ldap_server_url' in opts:
            config['server url'] = opts['ldap_server_url']
        if 'ldap_bind_dn_template' in opts:
            config['bind dn template'] = opts['ldap_bind_dn_template']
        config['tls'] = 'Demand'
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
        order.append('ldap')
        globalconf['order'] = ','.join(order)
        po.set_config(globalconf)
        po.save_plugin_config(FACILITY)
