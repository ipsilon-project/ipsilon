# Copyright (C) 2014 Ipsilon project Contributors, for license see COPYING

from __future__ import absolute_import

from ipsilon.providers.common import ProviderBase, ProviderInstaller
from ipsilon.util.plugin import PluginObject
from ipsilon.util import config as pconfig
from ipsilon.info.common import InfoMapping
from ipsilon.providers.persona.auth import Persona
from ipsilon.tools import files

import json
import M2Crypto
import os


class IdpProvider(ProviderBase):

    def __init__(self, *pargs):
        super(IdpProvider, self).__init__('persona', 'persona', *pargs)
        self.mapping = InfoMapping()
        self.page = None
        self.basepath = None
        self.key = None
        self.key_info = None
        self.description = """
Provides Persona authentication infrastructure. """

        self.new_config(
            self.name,
            pconfig.String(
                'issuer domain',
                'The issuer domain of the Persona provider',
                'localhost'),
            pconfig.String(
                'idp key file',
                'The key where the Persona key is stored.',
                'persona.key'),
            pconfig.List(
                'allowed domains',
                'List of domains this IdP is willing to issue claims for.'),
        )

    @property
    def issuer_domain(self):
        return self.get_config_value('issuer domain')

    @property
    def idp_key_file(self):
        return self.get_config_value('idp key file')

    @property
    def allowed_domains(self):
        return self.get_config_value('allowed domains')

    def get_tree(self, site):
        self.init_idp()
        self.page = Persona(site, self)
        # self.admin = AdminPage(site, self)

        return self.page

    def init_idp(self):
        # Init IDP data
        try:
            self.key = M2Crypto.RSA.load_key(self.idp_key_file,
                                             lambda *args: None)
        except Exception, e:  # pylint: disable=broad-except
            self.debug('Failed to init Persona provider: %r' % e)
            return None

    def on_enable(self):
        super(IdpProvider, self).on_enable()
        self.init_idp()


class Installer(ProviderInstaller):

    def __init__(self, *pargs):
        super(Installer, self).__init__()
        self.name = 'persona'
        self.pargs = pargs

    def install_args(self, group):
        group.add_argument('--persona', choices=['yes', 'no'], default='yes',
                           help='Configure Persona Provider')

    def configure(self, opts, changes):
        if opts['persona'] != 'yes':
            return

        # Check storage path is present or create it
        path = os.path.join(opts['data_dir'], 'persona')
        if not os.path.exists(path):
            os.makedirs(path, 0700)

        keyfile = os.path.join(path, 'persona.key')
        exponent = 0x10001
        key = M2Crypto.RSA.gen_key(2048, exponent)
        key.save_key(keyfile, cipher=None)
        key_n = 0
        for c in key.n[4:]:
            key_n = (key_n*256) + ord(c)
        wellknown = dict()
        wellknown['authentication'] = '/%s/persona/SignIn/' % opts['instance']
        wellknown['provisioning'] = '/%s/persona/' % opts['instance']
        wellknown['public-key'] = {'algorithm': 'RS',
                                   'e': str(exponent),
                                   'n': str(key_n)}
        with open(os.path.join(opts['wellknown_dir'], 'browserid'), 'w') as f:
            f.write(json.dumps(wellknown))

        # Add configuration data to database
        po = PluginObject(*self.pargs)
        po.name = 'persona'
        po.wipe_data()
        po.wipe_config_values()
        config = {'issuer domain': opts['hostname'],
                  'idp key file': keyfile,
                  'allowed domains': opts['hostname']}
        po.save_plugin_config(config)

        # Update global config to add login plugin
        po.is_enabled = True
        po.save_enabled_state()

        # Fixup permissions so only the ipsilon user can read these files
        files.fix_user_dirs(path, opts['system_user'])
