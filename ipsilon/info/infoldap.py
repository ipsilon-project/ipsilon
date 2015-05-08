# Copyright (C) 2014 Ipsilon project Contributors, for license see COPYING

from ipsilon.info.common import InfoProviderBase
from ipsilon.info.common import InfoProviderInstaller
from ipsilon.util.plugin import PluginObject
from ipsilon.util.policy import Policy
from ipsilon.util import config as pconfig
import ldap
import subprocess


# TODO: fetch mapping from configuration
ldap_mapping = [
    ['cn', 'fullname'],
    ['commonname', 'fullname'],
    ['sn', 'surname'],
    ['mail', 'email'],
    ['destinationindicator', 'country'],
    ['postalcode', 'postcode'],
    ['st', 'state'],
    ['statetorprovincename', 'state'],
    ['streetaddress', 'street'],
    ['telephonenumber', 'phone'],
]


class InfoProvider(InfoProviderBase):

    def __init__(self, *pargs):
        super(InfoProvider, self).__init__(*pargs)
        self.mapper = Policy(ldap_mapping)
        self.name = 'ldap'
        self.description = """
Info plugin that uses LDAP to retrieve user data. """
        self.new_config(
            self.name,
            pconfig.String(
                'server url',
                'The LDAP server url.',
                'ldap://example.com'),
            pconfig.Template(
                'user dn template',
                'Template to turn username into DN.',
                'uid=%(username)s,ou=People,dc=example,dc=com'),
            pconfig.Pick(
                'tls',
                'What TLS level show be required',
                ['Demand', 'Allow', 'Try', 'Never', 'NoTLS'],
                'Demand'),
            pconfig.String(
                'bind dn',
                'DN to bind as, if empty uses anonymous bind.',
                'uid=ipsilon,ou=People,dc=example,dc=com'),
            pconfig.String(
                'bind password',
                'Password to use for bind operation'),
            pconfig.String(
                'base dn',
                'The base dn to look for users and groups',
                'dc=example,dc=com'),
        )

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

    @property
    def base_dn(self):
        return self.get_config_value('base dn')

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

    def _get_user_data(self, conn, dn):
        result = conn.search_s(dn, ldap.SCOPE_BASE)
        if result is None or result == []:
            raise Exception('User object could not be found!')
        elif len(result) > 1:
            raise Exception('No unique user object could be found!')
        data = dict()
        for name, value in result[0][1].iteritems():
            if isinstance(value, list) and len(value) == 1:
                value = value[0]
            data[name] = value
        return data

    def _get_user_groups(self, conn, base, username):
        # TODO: fixme to support RFC2307bis schemas
        results = conn.search_s(base, ldap.SCOPE_SUBTREE,
                                filterstr='memberuid=%s' % username)
        if results is None or results == []:
            self.debug('No groups for %s' % username)
            return []
        groups = []
        for r in results:
            if 'cn' in r[1]:
                groups.append(r[1]['cn'][0])
        return groups

    def get_user_data_from_conn(self, conn, dn, base, username):
        reply = dict()
        try:
            ldapattrs = self._get_user_data(conn, dn)
            self.debug(ldapattrs)
            userattrs, extras = self.mapper.map_attributes(ldapattrs)
            groups = self._get_user_groups(conn, base, username)
            reply = userattrs
            reply['_groups'] = groups
            reply['_extras'] = {'ldap': extras}
        except Exception, e:  # pylint: disable=broad-except
            self.error(e)

        return reply

    def get_user_attrs(self, user):
        try:
            conn = self._ldap_bind()
            dn = self.user_dn_tmpl % {'username': user}
            base = self.base_dn
            return self.get_user_data_from_conn(conn, dn, base, user)
        except Exception, e:  # pylint: disable=broad-except
            self.error(e)
            return {}


class Installer(InfoProviderInstaller):

    def __init__(self, *pargs):
        super(Installer, self).__init__()
        self.name = 'ldap'
        self.pargs = pargs

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
        group.add_argument('--info-ldap-base-dn', action='store',
                           help='LDAP Base DN')

    def configure(self, opts, changes):
        if opts['info_ldap'] != 'yes':
            return

        # Add configuration data to database
        po = PluginObject(*self.pargs)
        po.name = 'ldap'
        po.wipe_data()
        po.wipe_config_values()
        config = dict()
        if 'info_ldap_server_url' in opts:
            config['server url'] = opts['info_ldap_server_url']
        elif 'ldap_server_url' in opts:
            config['server url'] = opts['ldap_server_url']
        if 'info_ldap_bind_dn' in opts:
            config['bind dn'] = opts['info_ldap_bind_dn']
        if 'info_ldap_bind_pwd' in opts:
            config['bind password'] = opts['info_ldap_bind_pwd']
        if 'info_ldap_user_dn_template' in opts:
            config['user dn template'] = opts['info_ldap_user_dn_template']
        elif 'ldap_bind_dn_template' in opts:
            config['user dn template'] = opts['ldap_bind_dn_template']
        if 'info_ldap_tls_level' in opts and opts['info_ldap_tls_level']:
            config['tls'] = opts['info_ldap_tls_level']
        elif 'ldap_tls_level' in opts and opts['ldap_tls_level']:
            config['tls'] = opts['ldap_tls_level']
        else:
            config['tls'] = 'Demand'
        if 'info_ldap_base_dn' in opts and opts['info_ldap_base_dn']:
            config['base dn'] = opts['info_ldap_base_dn']
        elif 'ldap_base_dn' in opts and opts['ldap_base_dn']:
            config['base dn'] = opts['ldap_base_dn']
        po.save_plugin_config(config)

        # Update global config to add info plugin
        po.is_enabled = True
        po.save_enabled_state()

        # For selinux enabled platforms permit httpd to connect to ldap,
        # ignore if it fails
        try:
            subprocess.call(['/usr/sbin/setsebool', '-P',
                             'httpd_can_connect_ldap=on'])
        except Exception:  # pylint: disable=broad-except
            pass
