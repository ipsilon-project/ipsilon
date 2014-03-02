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
from ipsilon.providers.saml2.auth import AuthenticateRequest
from ipsilon.util.user import UserSession
import cherrypy
import lasso
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
            login = lasso.Login.newFromDump(self.cfg.idp, dump)
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


class SAML2(ProviderPageBase):

    def __init__(self, *args, **kwargs):
        super(SAML2, self).__init__(*args, **kwargs)

        # Init IDP data
        try:
            self.cfg.idp = lasso.Server(self.cfg.idp_metadata_file,
                                        self.cfg.idp_key_file,
                                        None,
                                        self.cfg.idp_certificate_file)
            self.cfg.idp.role = lasso.PROVIDER_ROLE_IDP
        except Exception, e:  # pylint: disable=broad-except
            self._debug('Failed to enable SAML2 provider: %r' % e)
            return

        # Import all known applications
        data = self.cfg.get_data()
        for idval in data:
            if 'type' not in data[idval] or data[idval]['type'] != 'SP':
                continue
            path = os.path.join(self.cfg.idp_storage_path, str(idval))
            sp = data[idval]
            if 'name' in sp:
                name = sp['name']
            else:
                name = str(idval)
            try:
                meta = os.path.join(path, 'metadata.xml')
                cert = os.path.join(path, 'certificate.pem')
                self.cfg.idp.addProvider(lasso.PROVIDER_ROLE_SP, meta, cert)
                self._debug('Added SP %s' % name)
            except Exception, e:  # pylint: disable=broad-except
                self._debug('Failed to add SP %s: %r' % (name, e))

        self.SSO = SSO(*args, **kwargs)


class IdpProvider(ProviderBase):

    def __init__(self):
        super(IdpProvider, self).__init__('saml2', 'saml2')
        self.page = None
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
        return self.page
