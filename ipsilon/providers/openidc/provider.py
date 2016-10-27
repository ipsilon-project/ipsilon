# Copyright (C) 2016 Ipsilon project Contributors, for license see COPYING

from ipsilon.providers.openidc.api import APIError, APIRequest
from ipsilon.util.security import generate_random_secure_string
import ipsilon.util.config as pconfig

import cherrypy
from jwcrypto.jws import default_allowed_algs as jws_default_allowed_algs
import json
import time
import requests
from urlparse import urlparse


def get_url_hostpart(url):
    try:
        o = urlparse(url)
        return o.hostname
    except:  # pylint: disable=bare-except
        return url


class Registration(APIRequest):

    def POST(self, *args, **kwargs):
        if not self.cfg.allow_dynamic_client_registration:
            raise APIError(400, 'invalid_request',
                           'dynamic client registration has been disabled')

        try:
            client_metadata = json.loads(cherrypy.request.rfile.read())
        except:
            raise APIError(400, 'invalid_client_metadata',
                           'unable to parse metadata')
        self.debug('Received client registration request: %s'
                   % client_metadata)

        if 'ipsilon_internal' in client_metadata:
            raise APIError(400, 'invalid_client_metadata',
                           'Internal information provided')

        try:
            clt = Client(client_metadata, trusted=False)
            clt.validate()
            clt.generate_secret()
        except InvalidMetadata as ex:
            raise APIError(400, 'invalid_client_metadata',
                           ex.message)
        except InvalidRedirectURI as ex:
            raise APIError(400, 'invalid_redirect_uri',
                           ex.message)
        except pconfig.FieldValueError as ex:
            raise APIError(400, 'invalid_request',
                           'invalid field value for %s' % ex.field)

        client_metadata = clt.generate()

        # Store and add reg uri
        client_id = self.cfg.datastore.registerDynamicClient(client_metadata)
        client_metadata['client_id'] = client_id

        # Clear internal data from returned values
        del client_metadata['ipsilon_internal']

        # FIXME: Offer this once we add a ClientConfiguration endpoint
        # client_metadata['registration_access_token'] = \
        #    generate_random_secure_string()
        # client_metadata['registration_client_uri'] = '%s%s' % (
        #    self.cfg.endpoint_url, 'ClientConfiguration')

        return self._respond(client_metadata)


class Client(pconfig.ConfigHelper):
    def __init__(self, client_info=None, trusted=True):
        super(Client, self).__init__()
        if client_info is None:
            client_info = {}
        self.client_info = client_info
        self.readonly = self.client_info.get('type', 'new') == 'dynamic'
        if 'ipsilon_internal' in client_info:
            self.client_id = client_info['ipsilon_internal']['client_id']
        else:
            self.client_id = None
            self.client_info['ipsilon_internal'] = {'trusted': trusted}

        self.load_config()

    def generate_secret(self, force=False):
        if 'client_secret' not in self.client_info or force:
            self.client_info['client_secret'] = \
                generate_random_secure_string()
            self.client_info['client_secret_expires_at'] = 0  # FIXME: Expire?
            self.client_info['client_id_issued_at'] = int(time.time())

    def generate(self):
        metadata = self.generate_public()

        self.generate_secret()
        metadata['client_secret'] = self.client_info['client_secret']
        metadata['client_secret_expires_at'] = \
            self.client_info['client_secret_expires_at']
        metadata['client_id_issued_at'] = \
            self.client_info['client_id_issued_at']
        metadata['ipsilon_internal'] = self.client_info['ipsilon_internal']

        # This is used to store values that the client provides that we do not
        # yet support, so that when we do support them in a future version, we
        # have not thrown them away.
        metadata['ipsilon_internal']['extra'] = \
            self.client_info['ipsilon_internal'].get('extra', {})
        for key in self.client_info:
            if key != 'ipsilon_internal' and key not in metadata:
                metadata['ipsilon_internal']['extra'][key] = \
                    self.client_info[key]
        return metadata

    def generate_public(self):
        metadata = {}
        for option, value in self.get_config_obj().iteritems():
            name = option.replace(' ', '_').lower()
            metadata[name] = value.get_value()
        return metadata

    def validate(self):
        conf = self.get_config_obj()
        if len(conf['Redirect URIs'].get_value()) == 0:
            raise InvalidMetadata('No Redirect URIs')

        if conf['Redirect URIs'].get_value() == ['']:
            raise InvalidMetadata('No Redirect URIs')

        for redirect_uri in conf['Redirect URIs'].get_value():
            if '#' in redirect_uri:
                raise InvalidRedirectURI('redirect_uri contains fragment')

            if conf['Application Type'].get_value() == 'web':
                # In this case, it must be https:// and not https://localhost
                if (not redirect_uri.startswith('https://') or
                        redirect_uri.startswith('https://localhost')):
                    raise InvalidRedirectURI('non-https or localhost with web')

            elif conf['Application Type'].get_value() == 'native':
                # In this case, it must be http://localhost, or something
                # that is not http:// or https://
                if (redirect_uri.startswith('https://') or
                        (redirect_uri.startswith('http://') and
                         not redirect_uri.startswith('http://localhost'))):
                    raise InvalidRedirectURI('http or https with native')

        if conf['Initiate Login URI'].get_value():
            ilu = conf['Initiate Login URI'].get_value()
            if not ilu.startswith('https://'):
                raise InvalidMetadata('Initiate Login URI does not start with '
                                      'https')

        if not conf['Sector Identifier URI'].get_value():
            hostname = None
            for redir_uri in conf['Redirect URIs'].get_value():
                cur_host = get_url_hostpart(redir_uri)
                if not cur_host:
                    raise InvalidRedirectURI('Unable to parse hostname from %s'
                                             % redir_uri)
                if hostname is not None and cur_host != hostname:
                    raise InvalidMetadata('Multiple redirect_uri hostnames '
                                          'without sector identifier')
                hostname = cur_host
        else:
            si_uri = conf['Sector Identifier URI'].get_value()
            if not si_uri.startswith('https://'):
                raise InvalidMetadata('Sector identifier URI must be https')

            try:
                resp = requests.get(si_uri)
                resp = resp.json()
                for redirect_uri in conf['Redirect URIs'].get_value():
                    if redirect_uri not in resp:
                        raise InvalidMetadata('Redirect URI %s not in sector '
                                              'identifier document'
                                              % redirect_uri)
            except Exception as ex:
                self.debug('Unable to retrieve sector identifiers: %s'
                           % repr(ex))
                raise InvalidMetadata('Unable to retrieve sector identifier')

        gtypes = conf['Grant Types'].get_value()
        for rtype in conf['Response Types'].get_value():
            if 'code' in rtype and 'authorization_code' not in gtypes:
                raise InvalidMetadata('authorization_code grant type missing '
                                      'for response type code')

            if 'token' in rtype and 'implicit' not in gtypes:
                raise InvalidMetadata('implicit grant type missing for '
                                      'response type token or id_token')

        if conf['JWKS'].get_value() and conf['JWKS URI'].get_value():
            raise InvalidMetadata('Both JWKs and JWKs URI are provided')

    def get_current_info(self, option):
        if option == 'client_id':
            return self.client_id or ''
        elif option in self.client_info:
            return self.client_info[option]
        elif option in self.client_info['ipsilon_internal'].get('extra', {}):
            # This was an option that was unsupported and stored to the side in
            # a previous release, but that we can now actually use.
            return self.client_info['ipsilon_internal']['extra'][option]
        elif option in ['redirect_uris', 'contacts', 'request_uris']:
            return []
        elif option == 'response_types':
            return ['code']
        elif option == 'grant_types':
            return ['authorization_code']
        elif option == 'application_type':
            return 'web'
        elif option == 'subject_type':
            return 'pairwise'
        elif option == 'require_auth_time':
            return False
        elif option == 'token_endpoint_auth_method':
            return 'client_secret_basic'
        elif option == 'id_token_signed_response_alg':
            return 'RS256'
        elif option == 'client_secret':
            if 'client_secret' in self.client_info:
                return self.client_info['client_secret']
            else:
                return '*Autogenerated*'
        elif option == 'default_max_age':
            return 0
        elif option == 'request_object_signing_alg':
            return 'none'
        else:
            return ''

    def load_config(self):
        self.new_config(
            self.client_id,
            pconfig.String(
                'Client ID',
                'Client Identifier used in the protocol.',
                self.get_current_info('client_id'),
                readonly=self.client_id is not None),
            pconfig.String(
                'Client Secret',
                'Client secret used to authenticate.',
                self.get_current_info('client_secret'),
                readonly=True),
            pconfig.String(
                'Client Name',
                'A nickname shown to the user to identify the client.',
                self.get_current_info('client_name'),
                readonly=self.readonly),
            pconfig.List(
                'Redirect URIs',
                'URIs to be used by the client as redirect URIs. Must all '
                'start with https if application type is web, must all start '
                'with http://localhost/ if application type is native.',
                self.get_current_info('redirect_uris'),
                readonly=self.readonly),
            pconfig.Pick(
                'Application Type',
                'Application type of the client.',
                ['web', 'native'],
                self.get_current_info('application_type'),
                readonly=self.readonly),
            pconfig.String(
                'Client URI',
                'URI of the home page of the client.',
                self.get_current_info('client_uri'),
                readonly=self.readonly),
            pconfig.List(
                'Contacts',
                'List of contacts email addressess for this client.',
                self.get_current_info('contacts'),
                readonly=self.readonly),
            pconfig.String(
                'Logo URI',
                'URI of the a logo for the client.',
                self.get_current_info('logo_uri'),
                readonly=self.readonly),
            pconfig.String(
                'Policy URI',
                'URI to the client privacy policy.',
                self.get_current_info('policy_uri'),
                readonly=self.readonly),
            pconfig.String(
                'TOS URI',
                'URI to the client Terms of Service.',
                self.get_current_info('tos_uri'),
                readonly=self.readonly),
            pconfig.String(
                'JWKS URI',
                'URI to the client JSON Web Key Set document.',
                self.get_current_info('jwks_uri'),
                readonly=self.readonly),
            pconfig.String(
                'JWKS',
                'Document with client JSON Web Key Set',
                self.get_current_info('jwks'),
                readonly=self.readonly,
                multiline=True),
            pconfig.String(
                'Sector Identifier URI',
                'URI identifying the pairwise subject value sector.',
                self.get_current_info('sector_identifier_uri'),
                readonly=self.readonly),
            pconfig.Pick(
                'Subject type',
                'Subject type to be used for this client',
                ['pairwise', 'public'],
                self.get_current_info('subject_type'),
                readonly=self.readonly),
            pconfig.Choice(
                'Response Types',
                'Response types that will be used',
                ['code', 'id_token', 'id_token token', 'code id_token',
                 'code token', 'code id_token token'],
                self.get_current_info('response_types'),
                readonly=self.readonly),
            pconfig.Choice(
                'Grant Types',
                'Grant types this client will use.',
                ['authorization_code', 'implicit', 'refresh_token'],
                self.get_current_info('grant_types'),
                readonly=self.readonly),
            pconfig.List(
                'Request URIs',
                'URIs used by the client containing request objects.',
                self.get_current_info('request_uris'),
                readonly=self.readonly),
            pconfig.Condition(
                'Require Auth Time',
                'Whether the client requires the last auth time.',
                self.get_current_info('require_auth_time'),
                readonly=self.readonly),
            pconfig.Pick(
                'Token Endpoint Auth Method',
                'Auth method used by the client to the token endpoint.',
                ['client_secret_post', 'client_secret_basic',
                 'client_secret_jwt', 'private_key_jwt', 'none'],
                self.get_current_info('token_endpoint_auth_method'),
                readonly=self.readonly),
            pconfig.Pick(
                'ID Token Signed Response Alg',
                'Algorithm used to sign ID Tokens',
                ['RS256'],
                self.get_current_info('id_token_signed_response_alg'),
                readonly=self.readonly),
            pconfig.Pick(
                'UserInfo Signed Response Alg',
                'Algorithm used to sign userinfo',
                ['', 'RS256'],
                self.get_current_info('userinfo_signed_response_alg'),
                readonly=self.readonly),
            pconfig.Pick(
                'Request Object Signing Alg',
                'Algorithm used to sign request objects',
                jws_default_allowed_algs + ['none'],
                self.get_current_info('request_object_signing_alg'),
                readonly=self.readonly),
            pconfig.String(
                'Initiate Login URI',
                'URI that third party can use to initiate login at client.',
                self.get_current_info('initiate_login_uri'),
                readonly=self.readonly),
            pconfig.Integer(
                'Default Max Age',
                'Default maximum age for authentication timeout',
                self.get_current_info('default_max_age'),
                readonly=self.readonly),
            pconfig.List(
                'Default ACR values',
                'Default Authentication Context Class requested by client.',
                self.get_current_info('default_acr_values'),
                readonly=self.readonly),
            # TODO:
            # id_token_encrypted_response_alg
            # id_token_encrypted_response_enc
            # userinfo_encrypted_response_alg
            # userinfo_encrypted_response_enc
            # request_object_encryption_alg
            # request_object_encryption_enc
            # token_endpoint_auth_signing_alg
        )


class InvalidMetadata(ValueError):
    pass


class InvalidRedirectURI(ValueError):
    pass
