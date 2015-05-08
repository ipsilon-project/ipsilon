# Copyright (C) 2014 Ipsilon project Contributors, for license see COPYING

from ipsilon.login.common import LoginFormBase, LoginManagerBase, \
    LoginManagerInstaller
from ipsilon.util.plugin import PluginObject
from ipsilon.util.log import Log
from ipsilon.util import config as pconfig
from ipsilon.info.infoldap import InfoProvider as LDAPInfo
import ldap
import subprocess


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
                self.ldap_info = LDAPInfo(self._site)

            base = self.lm.base_dn
            return self.ldap_info.get_user_data_from_conn(conn, dn, base,
                                                          username)

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
        self.lm.set_auth_error()
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
        self.new_config(
            self.name,
            pconfig.String(
                'server url',
                'The LDAP server url.',
                'ldap://example.com'),
            pconfig.Template(
                'bind dn template',
                'Template to turn username into DN.',
                'uid=%(username)s,ou=People,dc=example,dc=com'),
            pconfig.String(
                'base dn',
                'The base dn to look for users and groups',
                'dc=example,dc=com'),
            pconfig.Condition(
                'get user info',
                'Get user info via ldap using user credentials',
                True),
            pconfig.Pick(
                'tls',
                'What TLS level show be required',
                ['Demand', 'Allow', 'Try', 'Never', 'NoTLS'],
                'Demand'),
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
                'Provide your Username and Password')
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
    def server_url(self):
        return self.get_config_value('server url')

    @property
    def tls(self):
        return self.get_config_value('tls')

    @property
    def get_user_info(self):
        return self.get_config_value('get user info')

    @property
    def bind_dn_tmpl(self):
        return self.get_config_value('bind dn template')

    @property
    def base_dn(self):
        return self.get_config_value('base dn')

    def get_tree(self, site):
        self.page = LDAP(site, self, 'login/ldap')
        return self.page


class Installer(LoginManagerInstaller):

    def __init__(self, *pargs):
        super(Installer, self).__init__()
        self.name = 'ldap'
        self.pargs = pargs

    def install_args(self, group):
        group.add_argument('--ldap', choices=['yes', 'no'], default='no',
                           help='Configure LDAP authentication')
        group.add_argument('--ldap-server-url', action='store',
                           help='LDAP Server Url')
        group.add_argument('--ldap-bind-dn-template', action='store',
                           help='LDAP Bind DN Template')
        group.add_argument('--ldap-tls-level', action='store', default=None,
                           help='LDAP TLS level')
        group.add_argument('--ldap-base-dn', action='store',
                           help='LDAP Base DN')

    def configure(self, opts, changes):
        if opts['ldap'] != 'yes':
            return

        # Add configuration data to database
        po = PluginObject(*self.pargs)
        po.name = 'ldap'
        po.wipe_data()
        po.wipe_config_values()

        config = dict()
        if 'ldap_server_url' in opts:
            config['server url'] = opts['ldap_server_url']
        if 'ldap_bind_dn_template' in opts:
            config['bind dn template'] = opts['ldap_bind_dn_template']
        if 'ldap_tls_level' in opts and opts['ldap_tls_level'] is not None:
            config['tls'] = opts['ldap_tls_level']
        else:
            config['tls'] = 'Demand'
        if 'ldap_base_dn' in opts and opts['ldap_base_dn'] is not None:
            config['base dn'] = opts['ldap_base_dn']
        po.save_plugin_config(config)

        # Update global config to add login plugin
        po.is_enabled = True
        po.save_enabled_state()

        # For selinux enabled platforms permit httpd to connect to ldap,
        # ignore if it fails
        try:
            subprocess.call(['/usr/sbin/setsebool', '-P',
                             'httpd_can_connect_ldap=on'])
        except Exception:  # pylint: disable=broad-except
            pass
