# Copyright (C) 2014  Simo Sorce <simo@redhat.com>
#
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from ipsilon.providers.common import ProviderBase, ProviderPageBase, \
    ProviderInstaller
from ipsilon.providers.saml2.auth import AuthenticateRequest
from ipsilon.providers.saml2.logout import LogoutRequest
from ipsilon.providers.saml2.admin import Saml2AdminPage
from ipsilon.providers.saml2.rest import Saml2RestBase
from ipsilon.providers.saml2.provider import IdentityProvider
from ipsilon.tools.certs import Certificate
from ipsilon.tools import saml2metadata as metadata
from ipsilon.tools import files
from ipsilon.util.user import UserSession
from ipsilon.util.plugin import PluginObject
from ipsilon.util import config as pconfig
import cherrypy
from datetime import timedelta
import lasso
import os
import time


class Redirect(AuthenticateRequest):

    def GET(self, *args, **kwargs):

        query = cherrypy.request.query_string

        login = self.saml2login(query)
        return self.auth(login)


class POSTAuth(AuthenticateRequest):

    def POST(self, *args, **kwargs):

        request = kwargs.get(lasso.SAML2_FIELD_REQUEST)
        relaystate = kwargs.get(lasso.SAML2_FIELD_RELAYSTATE)

        login = self.saml2login(request)
        login.set_msgRelayState(relaystate)
        return self.auth(login)


class Continue(AuthenticateRequest):

    def GET(self, *args, **kwargs):

        session = UserSession()
        user = session.get_user()
        transdata = self.trans.retrieve()
        self.stage = transdata['saml2_stage']

        if user.is_anonymous:
            self._debug("User is marked anonymous?!")
            # TODO: Return to SP with auth failed error
            raise cherrypy.HTTPError(401)

        self._debug('Continue auth for %s' % user.name)

        if 'saml2_request' not in transdata:
            self._debug("Couldn't find Request dump?!")
            # TODO: Return to SP with auth failed error
            raise cherrypy.HTTPError(400)
        dump = transdata['saml2_request']

        try:
            login = self.cfg.idp.get_login_handler(dump)
        except Exception, e:  # pylint: disable=broad-except
            self._debug('Failed to load status from dump: %r' % e)

        if not login:
            self._debug("Empty Request dump?!")
            # TODO: Return to SP with auth failed error
            raise cherrypy.HTTPError(400)

        return self.auth(login)


class RedirectLogout(LogoutRequest):

    def GET(self, *args, **kwargs):
        query = cherrypy.request.query_string

        relaystate = kwargs.get(lasso.SAML2_FIELD_RELAYSTATE)
        response = kwargs.get(lasso.SAML2_FIELD_RESPONSE)

        return self.logout(query,
                           relaystate=relaystate,
                           samlresponse=response)


class SSO(ProviderPageBase):

    def __init__(self, *args, **kwargs):
        super(SSO, self).__init__(*args, **kwargs)
        self.Redirect = Redirect(*args, **kwargs)
        self.POST = POSTAuth(*args, **kwargs)
        self.Continue = Continue(*args, **kwargs)


class SLO(ProviderPageBase):

    def __init__(self, *args, **kwargs):
        super(SLO, self).__init__(*args, **kwargs)
        self._debug('SLO init')
        self.Redirect = RedirectLogout(*args, **kwargs)


# one week
METADATA_RENEW_INTERVAL = 60 * 60 * 24 * 7
# 30 days
METADATA_VALIDITY_PERIOD = 30


class Metadata(ProviderPageBase):
    def GET(self, *args, **kwargs):

        body = self._get_metadata()
        cherrypy.response.headers["Content-Type"] = "text/xml"
        cherrypy.response.headers["Content-Disposition"] = \
            'attachment; filename="metadata.xml"'
        return body

    def _get_metadata(self):
        if os.path.isfile(self.cfg.idp_metadata_file):
            s = os.stat(self.cfg.idp_metadata_file)
            if s.st_mtime > time.time() - METADATA_RENEW_INTERVAL:
                with open(self.cfg.idp_metadata_file) as m:
                    return m.read()

        # Otherwise generate and save
        idp_cert = Certificate()
        idp_cert.import_cert(self.cfg.idp_certificate_file,
                             self.cfg.idp_key_file)
        meta = IdpMetadataGenerator(self.instance_base_url(), idp_cert,
                                    timedelta(METADATA_VALIDITY_PERIOD))
        body = meta.output()
        with open(self.cfg.idp_metadata_file, 'w+') as m:
            m.write(body)
        return body


class SAML2(ProviderPageBase):

    def __init__(self, *args, **kwargs):
        super(SAML2, self).__init__(*args, **kwargs)
        self.metadata = Metadata(*args, **kwargs)
        self.SSO = SSO(*args, **kwargs)
        self.SLO = SLO(*args, **kwargs)


class IdpProvider(ProviderBase):

    def __init__(self, *pargs):
        super(IdpProvider, self).__init__('saml2', 'saml2', *pargs)
        self.admin = None
        self.rest = None
        self.page = None
        self.idp = None
        self.description = """
Provides SAML 2.0 authentication infrastructure. """

        self.new_config(
            self.name,
            pconfig.String(
                'idp storage path',
                'Path to data storage accessible by the IdP.',
                '/var/lib/ipsilon/saml2'),
            pconfig.String(
                'idp metadata file',
                'The IdP Metadata file genearated at install time.',
                'metadata.xml'),
            pconfig.String(
                'idp certificate file',
                'The IdP PEM Certificate genearated at install time.',
                'certificate.pem'),
            pconfig.String(
                'idp key file',
                'The IdP Certificate Key genearated at install time.',
                'certificate.key'),
            pconfig.Condition(
                'allow self registration',
                'Allow authenticated users to register applications.',
                True),
            pconfig.Choice(
                'default allowed nameids',
                'Default Allowed NameIDs for Service Providers.',
                metadata.SAML2_NAMEID_MAP.keys(),
                ['persistent', 'transient', 'email', 'kerberos', 'x509']),
            pconfig.Pick(
                'default nameid',
                'Default NameID used by Service Providers.',
                metadata.SAML2_NAMEID_MAP.keys(),
                'persistent'),
            pconfig.String(
                'default email domain',
                'Used for users missing the email property.',
                'example.com'),
            pconfig.MappingList(
                'default attribute mapping',
                'Defines how to map attributes before returning them to SPs',
                [['*', '*']]),
            pconfig.ComplexList(
                'default allowed attributes',
                'Defines a list of allowed attributes, applied after mapping',
                ['*']),
        )
        if cherrypy.config.get('debug', False):
            import logging
            import sys
            logger = logging.getLogger('lasso')
            lh = logging.StreamHandler(sys.stderr)
            logger.addHandler(lh)
            logger.setLevel(logging.DEBUG)

    @property
    def allow_self_registration(self):
        return self.get_config_value('allow self registration')

    @property
    def idp_storage_path(self):
        return self.get_config_value('idp storage path')

    @property
    def idp_metadata_file(self):
        return os.path.join(self.idp_storage_path,
                            self.get_config_value('idp metadata file'))

    @property
    def idp_certificate_file(self):
        return os.path.join(self.idp_storage_path,
                            self.get_config_value('idp certificate file'))

    @property
    def idp_key_file(self):
        return os.path.join(self.idp_storage_path,
                            self.get_config_value('idp key file'))

    @property
    def default_allowed_nameids(self):
        return self.get_config_value('default allowed nameids')

    @property
    def default_nameid(self):
        return self.get_config_value('default nameid')

    @property
    def default_email_domain(self):
        return self.get_config_value('default email domain')

    @property
    def default_attribute_mapping(self):
        return self.get_config_value('default attribute mapping')

    @property
    def default_allowed_attributes(self):
        return self.get_config_value('default allowed attributes')

    def get_tree(self, site):
        self.idp = self.init_idp()
        self.page = SAML2(site, self)
        self.admin = Saml2AdminPage(site, self)
        self.rest = Saml2RestBase(site, self)
        return self.page

    def init_idp(self):
        idp = None
        # Init IDP data
        try:
            idp = IdentityProvider(self)
        except Exception, e:  # pylint: disable=broad-except
            self._debug('Failed to init SAML2 provider: %r' % e)
            return None

        # Import all known applications
        data = self.get_data()
        for idval in data:
            sp = data[idval]
            if 'type' not in sp or sp['type'] != 'SP':
                continue
            if 'name' not in sp or 'metadata' not in sp:
                continue
            try:
                idp.add_provider(sp)
            except Exception, e:  # pylint: disable=broad-except
                self._debug('Failed to add SP %s: %r' % (sp['name'], e))

        return idp

    def on_enable(self):
        super(IdpProvider, self).on_enable()
        self.idp = self.init_idp()
        if hasattr(self, 'admin'):
            if self.admin:
                self.admin.add_sps()


class IdpMetadataGenerator(object):

    def __init__(self, url, idp_cert, expiration=None):
        self.meta = metadata.Metadata(metadata.IDP_ROLE, expiration)
        self.meta.set_entity_id('%s/saml2/metadata' % url)
        self.meta.add_certs(idp_cert, idp_cert)
        self.meta.add_service(metadata.SAML2_SERVICE_MAP['sso-post'],
                              '%s/saml2/SSO/POST' % url)
        self.meta.add_service(metadata.SAML2_SERVICE_MAP['sso-redirect'],
                              '%s/saml2/SSO/Redirect' % url)
        self.meta.add_service(metadata.SAML2_SERVICE_MAP['logout-redirect'],
                              '%s/saml2/SLO/Redirect' % url)
        self.meta.add_allowed_name_format(
            lasso.SAML2_NAME_IDENTIFIER_FORMAT_TRANSIENT)
        self.meta.add_allowed_name_format(
            lasso.SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT)
        self.meta.add_allowed_name_format(
            lasso.SAML2_NAME_IDENTIFIER_FORMAT_EMAIL)

    def output(self, path=None):
        return self.meta.output(path)


class Installer(ProviderInstaller):

    def __init__(self, *pargs):
        super(Installer, self).__init__()
        self.name = 'saml2'
        self.pargs = pargs

    def install_args(self, group):
        group.add_argument('--saml2', choices=['yes', 'no'], default='yes',
                           help='Configure SAML2 Provider')

    def configure(self, opts):
        if opts['saml2'] != 'yes':
            return

        # Check storage path is present or create it
        path = os.path.join(opts['data_dir'], 'saml2')
        if not os.path.exists(path):
            os.makedirs(path, 0700)

        # Use the same cert for signing and ecnryption for now
        cert = Certificate(path)
        cert.generate('idp', opts['hostname'])

        # Generate Idp Metadata
        proto = 'https'
        if opts['secure'].lower() == 'no':
            proto = 'http'
        url = '%s://%s/%s' % (proto, opts['hostname'], opts['instance'])
        meta = IdpMetadataGenerator(url, cert,
                                    timedelta(METADATA_VALIDITY_PERIOD))
        if 'krb' in opts and opts['krb'] == 'yes':
            meta.meta.add_allowed_name_format(
                lasso.SAML2_NAME_IDENTIFIER_FORMAT_KERBEROS)

        meta.output(os.path.join(path, 'metadata.xml'))

        # Add configuration data to database
        po = PluginObject(*self.pargs)
        po.name = 'saml2'
        po.wipe_data()
        po.wipe_config_values()
        config = {'idp storage path': path,
                  'idp metadata file': 'metadata.xml',
                  'idp certificate file': cert.cert,
                  'idp key file': cert.key}
        po.save_plugin_config(config)

        # Update global config to add login plugin
        po.is_enabled = True
        po.save_enabled_state()

        # Fixup permissions so only the ipsilon user can read these files
        files.fix_user_dirs(path, opts['system_user'])
