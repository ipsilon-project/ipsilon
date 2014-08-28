#!/usr/bin/python
#
# Copyright (C) 2014 Ipsilon Project Contributors
#
# See the file named COPYING for the project license

from ipsilon.info.common import InfoProviderBase
from ipsilon.info.common import InfoProviderInstaller
from ipsilon.util.plugin import PluginObject
from ipsilon.util.log import Log
import ldap


class InfoProvider(InfoProviderBase, Log):

    def __init__(self):
        super(InfoProvider, self).__init__()
        self.name = 'ldap'
        self.description = """
Info plugin that uses LDAP to retrieve user data. """
        self._options = {
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
            'bind dn': [
                """ User DN to bind as, if empty uses anonymous bind. """,
                'string',
                'uid=ipsilon,ou=People,dc=example,dc=com'
            ],
            'bind password': [
                """ Password to use for bind operation """,
                'string',
                'Password'
            ],
            'user dn template': [
                """ Template to turn username into DN. """,
                'string',
                'uid=%(username)s,ou=People,dc=example,dc=com'
            ],
        }

    @property
    def server_url(self):
        return self.get_config_value('server url')

    @property
    def tls(self):
        return self.get_config_value('tls')

    @property
    def bind_dn(self):
        return self.get_config_value('bind dn')

    @property
    def bind_password(self):
        return self.get_config_value('bind password')

    @property
    def user_dn_tmpl(self):
        return self.get_config_value('user dn template')

    def _ldap_bind(self):

        tls = self.tls.lower()
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

        conn = ldap.initialize(self.server_url)

        if tls != "notls":
            if not self.server_url.startswith("ldaps"):
                conn.start_tls_s()

        conn.simple_bind_s(self.bind_dn, self.bind_password)

        return conn

    def get_user_data_from_conn(self, conn, dn):
        result = conn.search_s(dn, ldap.SCOPE_BASE)
        if result is None or result == []:
            raise Exception('User object could not be found!')
        elif len(result) > 1:
            raise Exception('No unique user object could be found!')
        return result[0][1]

    def get_user_attrs(self, user):
        userattrs = None
        try:
            conn = self._ldap_bind()
            dn = self.user_dn_tmpl % {'username': user}
            userattrs = self.get_user_data_from_conn(conn, dn)
        except Exception, e:  # pylint: disable=broad-except
            self.error(e)

        return userattrs


class Installer(InfoProviderInstaller):

    def __init__(self):
        super(Installer, self).__init__()
        self.name = 'nss'

    def install_args(self, group):
        group.add_argument('--info-ldap', choices=['yes', 'no'], default='no',
                           help='Use LDAP to populate user attrs')
        group.add_argument('--info-ldap-server-url', action='store',
                           help='LDAP Server Url')
        group.add_argument('--info-ldap-bind-dn', action='store',
                           help='LDAP Bind DN')
        group.add_argument('--info-ldap-bind-pwd', action='store',
                           help='LDAP Bind Password')
        group.add_argument('--info-ldap-user-dn-template', action='store',
                           help='LDAP User DN Template')

    def configure(self, opts):
        if opts['info_ldap'] != 'yes':
            return

        # Add configuration data to database
        po = PluginObject()
        po.name = 'ldap'
        po.wipe_data()
        po.wipe_config_values(self.facility)
        config = dict()
        if 'info_ldap_server_url' in opts:
            config['server url'] = opts['info_ldap_server_url']
        elif 'ldap_server_url' in opts:
            config['server url'] = opts['ldap_server_url']
        config = {'bind dn': opts['info_ldap_bind_dn']}
        config = {'bind password': opts['info_ldap_bind_pwd']}
        config = {'user dn template': opts['info_ldap_user_dn_template']}
        if 'info_ldap_bind_dn' in opts:
            config['bind dn'] = opts['info_ldap_bind_dn']
        if 'info_ldap_bind_pwd' in opts:
            config['bind password'] = opts['info_ldap_bind_pwd']
        if 'info_ldap_user_dn_template' in opts:
            config['user dn template'] = opts['info_ldap_user_dn_template']
        elif 'ldap_bind_dn_template' in opts:
            config['user dn template'] = opts['ldap_bind_dn_template']
        config['tls'] = 'Demand'
        po.set_config(config)
        po.save_plugin_config(self.facility)

        # Replace global config, only one plugin info can be used
        po.name = 'global'
        globalconf = po.get_plugin_config(self.facility)
        if 'order' in globalconf:
            order = globalconf['order'].split(',')
        else:
            order = []
        order.append('ldap')
        globalconf['order'] = ','.join(order)
        po.set_config(globalconf)
        po.save_plugin_config(self.facility)
