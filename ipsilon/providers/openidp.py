# Copyright (C) 2014 Ipsilon project Contributors, for license see COPYING

from __future__ import absolute_import

from ipsilon.providers.common import ProviderBase, ProviderInstaller
from ipsilon.providers.openid.store import OpenIDStore
from ipsilon.providers.openid.auth import OpenID
from ipsilon.providers.openid.extensions.common import LoadExtensions
from ipsilon.util.plugin import PluginObject
from ipsilon.util import config as pconfig
from ipsilon.info.common import InfoMapping

from openid.server.server import Server


class IdpProvider(ProviderBase):

    def __init__(self, *pargs):
        super(IdpProvider, self).__init__('openid', 'openid', *pargs)
        self.mapping = InfoMapping()
        self.page = None
        self.server = None
        self.basepath = None
        self.extensions = LoadExtensions()
        self.description = """
Provides OpenID 2.0 authentication infrastructure. """

        self.new_config(
            self.name,
            pconfig.String(
                'database url',
                'Database URL for OpenID temp storage',
                'openid.sqlite'),
            pconfig.String(
                'default email domain',
                'Used for users missing the email property.',
                'example.com'),
            pconfig.String(
                'endpoint url',
                'The Absolute URL of the OpenID provider',
                'http://localhost:8080/idp/openid/'),
            pconfig.Template(
                'identity url template',
                'The templated URL where identities are exposed.',
                'http://localhost:8080/idp/openid/id/%(username)s'),
            pconfig.List(
                'trusted roots',
                'List of trusted relying parties.'),
            pconfig.List(
                'untrusted roots',
                'List of untrusted relying parties.'),
            pconfig.Choice(
                'enabled extensions',
                'Choose the extensions to enable',
                self.extensions.available().keys()),
            pconfig.MappingList(
                'default attribute mapping',
                'Defines how to map attributes before calling extensions',
                [['*', '*']]),
            pconfig.ComplexList(
                'default allowed attributes',
                'Defines a list of allowed attributes, applied after mapping',
                ['*']),
        )

    @property
    def endpoint_url(self):
        url = self.get_config_value('endpoint url')
        if url.endswith('/'):
            return url
        else:
            return url+'/'

    @property
    def default_email_domain(self):
        return self.get_config_value('default email domain')

    @property
    def identity_url_template(self):
        url = self.get_config_value('identity url template')
        if url.endswith('/'):
            return url
        else:
            return url+'/'

    @property
    def trusted_roots(self):
        return self.get_config_value('trusted roots')

    @property
    def untrusted_roots(self):
        return self.get_config_value('untrusted roots')

    @property
    def enabled_extensions(self):
        return self.get_config_value('enabled extensions')

    @property
    def default_attribute_mapping(self):
        return self.get_config_value('default attribute mapping')

    @property
    def default_allowed_attributes(self):
        return self.get_config_value('default allowed attributes')

    def get_tree(self, site):
        self.init_idp()
        self.page = OpenID(site, self)
        # self.admin = AdminPage(site, self)

        return self.page

    def init_idp(self):
        self.server = Server(
            OpenIDStore(self.get_config_value('database url')),
            op_endpoint=self.endpoint_url)

        # Expose OpenID presence in the root
        headers = self._root.default_headers
        headers['X-XRDS-Location'] = self.endpoint_url+'XRDS'

        html_heads = self._root.html_heads
        HEAD_LINK = '<link rel="%s" href="%s">'
        openid_heads = [HEAD_LINK % ('openid2.provider', self.endpoint_url),
                        HEAD_LINK % ('openid.server', self.endpoint_url)]
        html_heads['openid'] = openid_heads

    def on_enable(self):
        super(IdpProvider, self).on_enable()
        self.init_idp()
        self.extensions.enable(self._config['enabled extensions'].get_value())


class Installer(ProviderInstaller):

    def __init__(self, *pargs):
        super(Installer, self).__init__()
        self.name = 'openid'
        self.pargs = pargs

    def install_args(self, group):
        group.add_argument('--openid', choices=['yes', 'no'], default='yes',
                           help='Configure OpenID Provider')
        group.add_argument('--openid-dburi',
                           help='OpenID database URI')
        group.add_argument('--openid-extensions', default='',
                           help='List of OpenID Extensions to enable')

    def configure(self, opts, changes):
        if opts['openid'] != 'yes':
            return

        proto = 'https'
        if opts['secure'].lower() == 'no':
            proto = 'http'
        url = '%s://%s/%s/openid/' % (
            proto, opts['hostname'], opts['instance'])

        # Add configuration data to database
        po = PluginObject(*self.pargs)
        po.name = 'openid'
        po.wipe_data()
        po.wipe_config_values()
        config = {'endpoint url': url,
                  'identity url template': '%sid/%%(username)s' % url,
                  'database url': opts['openid_dburi'] or
                  opts['database_url'] % {
                      'datadir': opts['data_dir'], 'dbname': 'openid'},
                  'enabled extensions': opts['openid_extensions']}
        po.save_plugin_config(config)

        # Update global config to add login plugin
        po.is_enabled = True
        po.save_enabled_state()
