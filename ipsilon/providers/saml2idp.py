#!/usr/bin/python
#
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

from ipsilon.providers.common import ProviderBase, ProviderPageBase
from ipsilon.providers.common import FACILITY
from ipsilon.providers.saml2.auth import AuthenticateRequest
from ipsilon.providers.saml2.admin import AdminPage
from ipsilon.providers.saml2.provider import IdentityProvider
from ipsilon.tools.certs import Certificate
from ipsilon.tools import saml2metadata as metadata
from ipsilon.util.user import UserSession
from ipsilon.util.plugin import PluginObject
import cherrypy
import lasso
import pwd
import os


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
        session.nuke_data('login', 'Return')
        self.stage = session.get_data('saml2', 'stage')

        if user.is_anonymous:
            self._debug("User is marked anonymous?!")
            # TODO: Return to SP with auth failed error
            raise cherrypy.HTTPError(401)

        self._debug('Continue auth for %s' % user.name)

        dump = session.get_data('saml2', 'Request')
        if not dump:
            self._debug("Couldn't find Request dump?!")
            # TODO: Return to SP with auth failed error
            raise cherrypy.HTTPError(400)

        try:
            login = self.cfg.idp.get_login_handler(dump)
        except Exception, e:  # pylint: disable=broad-except
            self._debug('Failed to load status from dump: %r' % e)

        if not login:
            self._debug("Empty Request dump?!")
            # TODO: Return to SP with auth failed error
            raise cherrypy.HTTPError(400)

        return self.auth(login)


class SSO(ProviderPageBase):

    def __init__(self, *args, **kwargs):
        super(SSO, self).__init__(*args, **kwargs)
        self.Redirect = Redirect(*args, **kwargs)
        self.POST = POSTAuth(*args, **kwargs)
        self.Continue = Continue(*args, **kwargs)


class Metadata(ProviderPageBase):
    def GET(self, *args, **kwargs):
        with open(self.cfg.idp_metadata_file) as m:
            body = m.read()
        cherrypy.response.headers["Content-Type"] = "text/xml"
        cherrypy.response.headers["Content-Disposition"] = \
            'attachment; filename="metadata.xml"'
        return body


class SAML2(ProviderPageBase):

    def __init__(self, *args, **kwargs):
        super(SAML2, self).__init__(*args, **kwargs)
        self.metadata = Metadata(*args, **kwargs)

        # Init IDP data
        try:
            self.cfg.idp = IdentityProvider(self.cfg)
        except Exception, e:  # pylint: disable=broad-except
            self._debug('Failed to init SAML2 provider: %r' % e)
            return

        # Import all known applications
        data = self.cfg.get_data()
        for idval in data:
            sp = data[idval]
            if 'type' not in sp or sp['type'] != 'SP':
                continue
            if 'name' not in sp or 'metadata' not in sp:
                continue
            try:
                self.cfg.idp.add_provider(sp)
            except Exception, e:  # pylint: disable=broad-except
                self._debug('Failed to add SP %s: %r' % (sp['name'], e))

        self.SSO = SSO(*args, **kwargs)


class IdpProvider(ProviderBase):

    def __init__(self):
        super(IdpProvider, self).__init__('saml2', 'saml2')
        self.page = None
        self.idp = None
        self.description = """
Provides SAML 2.0 authentication infrastructure. """

        self._options = {
            'idp storage path': [
                """ Path to data storage accessible by the IdP """,
                'string',
                '/var/lib/ipsilon/saml2'
            ],
            'idp metadata file': [
                """ The IdP Metadata file genearated at install time. """,
                'string',
                'metadata.xml'
            ],
            'idp certificate file': [
                """ The IdP PEM Certificate genearated at install time. """,
                'string',
                'certificate.pem'
            ],
            'idp key file': [
                """ The IdP Certificate Key genearated at install time. """,
                'string',
                'certificate.key'
            ],
            'allow self registration': [
                """ Allow authenticated users to register applications. """,
                'boolean',
                True
            ],
            'default allowed nameids': [
                """Default Allowed NameIDs for Service Providers. """,
                'list',
                ['persistent', 'transient', 'email', 'kerberos', 'x509']
            ],
            'default nameid': [
                """Default NameID used by Service Providers. """,
                'string',
                'persistent'
            ],
            'default email domain': [
                """Default email domain, for users missing email property.""",
                'string',
                'example.com'
            ]
        }
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

    def get_tree(self, site):
        self.page = SAML2(site, self)
        self.admin = AdminPage(site, self)
        return self.page


class Installer(object):

    def __init__(self):
        self.name = 'saml2'
        self.ptype = 'provider'

    def install_args(self, group):
        group.add_argument('--saml2', choices=['yes', 'no'], default='yes',
                           help='Configure SAML2 Provider')
        group.add_argument('--saml2-storage',
                           default='/var/lib/ipsilon/saml2',
                           help='SAML2 Provider storage area')

    def configure(self, opts):
        if opts['saml2'] != 'yes':
            return

        # Check storage path is present or create it
        path = opts['saml2_storage']
        if not os.path.exists(path):
            os.makedirs(path, 0700)

        # Use the same cert for signing and ecnryption for now
        cert = Certificate(path)
        cert.generate('idp', opts['hostname'])

        # Generate Idp Metadata
        url = 'https://' + opts['hostname'] + '/idp/saml2'
        meta = metadata.Metadata(metadata.IDP_ROLE)
        meta.set_entity_id(url + '/metadata')
        meta.add_certs(cert, cert)
        meta.add_service(metadata.SAML2_SERVICE_MAP['sso-post'],
                         url + 'SSO/POST')
        meta.add_service(metadata.SAML2_SERVICE_MAP['sso-redirect'],
                         url + 'SSO/Redirect')

        meta.add_allowed_name_format(
            lasso.SAML2_NAME_IDENTIFIER_FORMAT_TRANSIENT)
        meta.add_allowed_name_format(
            lasso.SAML2_NAME_IDENTIFIER_FORMAT_PERSISTENT)
        meta.add_allowed_name_format(
            lasso.SAML2_NAME_IDENTIFIER_FORMAT_EMAIL)
        if 'krb' in opts and opts['krb'] == 'yes':
            meta.add_allowed_name_format(
                lasso.SAML2_NAME_IDENTIFIER_FORMAT_KERBEROS)

        meta.output(os.path.join(path, 'metadata.xml'))

        # Add configuration data to database
        po = PluginObject()
        po.name = 'saml2'
        po.wipe_data()

        po.wipe_config_values(FACILITY)
        config = {'idp storage path': path,
                  'idp metadata file': 'metadata.xml',
                  'idp certificate file': cert.cert,
                  'idp key file': cert.key}
        po.set_config(config)
        po.save_plugin_config(FACILITY)

        # Fixup permissions so only the ipsilon user can read these files
        pw = pwd.getpwnam(opts['system_user'])
        for root, dirs, files in os.walk(path):
            for name in dirs:
                target = os.path.join(root, name)
                os.chown(target, pw.pw_uid, pw.pw_gid)
                os.chmod(target, 0700)
            for name in files:
                target = os.path.join(root, name)
                os.chown(target, pw.pw_uid, pw.pw_gid)
                os.chmod(target, 0600)
