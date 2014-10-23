#!/usr/bin/python
#
# Copyright (C) 2014  Ipsilon project Contributors, for licensee see COPYING

from __future__ import absolute_import

from ipsilon.providers.common import ProviderBase
from ipsilon.providers.common import FACILITY
from ipsilon.providers.openid.auth import OpenID
from ipsilon.providers.openid.extensions.common import LoadExtensions
from ipsilon.util.plugin import PluginObject
from ipsilon.util import config as pconfig
from ipsilon.info.common import InfoMapping

from openid.server.server import Server
# TODO: Move this to the database
from openid.store.memstore import MemoryStore


class IdpProvider(ProviderBase):

    def __init__(self):
        super(IdpProvider, self).__init__('openid', 'openid')
        self.mapping = InfoMapping()
        self.page = None
        self.server = None
        self.basepath = None
        self.extensions = LoadExtensions()
        print self.extensions.available()
        print self.extensions.available().keys()
        self.description = """
Provides OpenID 2.0 authentication infrastructure. """

        self.new_config(
            self.name,
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
            pconfig.Condition(
                'enabled',
                'Whether the OpenID IDP is enabled',
                False)
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

    def get_tree(self, site):
        self.init_idp()
        self.page = OpenID(site, self)
        # self.admin = AdminPage(site, self)

        # Expose OpenID presence in the root
        headers = site[FACILITY]['root'].default_headers
        headers['X-XRDS-Location'] = self.endpoint_url+'XRDS'

        html_heads = site[FACILITY]['root'].html_heads
        HEAD_LINK = '<link rel="%s" href="%s">'
        openid_heads = [HEAD_LINK % ('openid2.provider', self.endpoint_url),
                        HEAD_LINK % ('openid.server', self.endpoint_url)]
        html_heads['openid'] = openid_heads

        return self.page

    def init_idp(self):
        self.server = Server(MemoryStore(), op_endpoint=self.endpoint_url)

    def on_enable(self):
        self.init_idp()
        self.extensions.enable(self._config['enabled extensions'].get_value())


class Installer(object):

    def __init__(self):
        self.name = 'openid'
        self.ptype = 'provider'

    def install_args(self, group):
        group.add_argument('--openid', choices=['yes', 'no'], default='yes',
                           help='Configure OpenID Provider')

    def configure(self, opts):
        if opts['openid'] != 'yes':
            return

        proto = 'https'
        if opts['secure'].lower() == 'no':
            proto = 'http'
        url = '%s://%s/%s/openid/' % (
            proto, opts['hostname'], opts['instance'])

        # Add configuration data to database
        po = PluginObject()
        po.name = 'openid'
        po.wipe_data()

        po.wipe_config_values(FACILITY)
        config = {'endpoint url': url,
                  'identity_url_template': '%sid/%%(username)s' % url,
                  'enabled': '1'}
        po.save_plugin_config(FACILITY, config)
