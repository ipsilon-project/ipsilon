# Copyright (C) 2016 Ipsilon project Contributors, for license see COPYING

from ipsilon.util.log import Log
from ipsilon.providers.common import ProviderPageBase
from ipsilon.util.security import constant_time_string_comparison

from jwcrypto.jwt import JWT
import base64
import cherrypy
import time
import json


class APIError(cherrypy.HTTPError, Log):

    def __init__(self, code, error, description=None):
        super(APIError, self).__init__(code, error)
        self.debug('OpenIDC API error: %s, desc: %s'
                   % (error, description))
        response = {'error': error}
        if description:
            response['error_description'] = description
        self._error_response = json.dumps(response)
        cherrypy.response.headers.update({
            'Content-Type': 'application/json'
        })

    def get_error_page(self, *args, **kwargs):
        return self._error_response


class APIRequest(ProviderPageBase):
    # Bearer token (RFC 6750) and Client Auth
    authenticate_client = False
    authenticate_token = False
    requires_client_auth = False
    requires_valid_token = False
    required_scope = None

    def __init__(self, site, provider, *args, **kwargs):
        super(APIRequest, self).__init__(site, provider)
        self.api_client_id = None
        self.api_valid_token = False
        self.api_username = None
        self.api_scopes = []
        self.api_client_authenticated = False
        self.api_client_id = None
        self.api_token = None
        self.api_client = None

    def pre_GET(self, *args, **kwargs):
        # Note that we explicitly do NOT support URI Query parameter posting
        # of bearer tokens (RFC6750, section 2.3 marks this as MAY)
        self._preop()

    def pre_POST(self, *args, **kwargs):
        self._preop(*args, **kwargs)

    def _preop(self, *args, **kwargs):
        cherrypy.response.headers.update({
            'Content-Type': 'application/json'
        })

        self.api_client_id = None
        self.api_valid_token = False
        self.api_username = None
        self.api_scopes = []
        self.api_client_authenticated = False
        self.api_client_id = None
        self.api_token = None
        self.api_client = None

        if self.authenticate_client:
            self._authenticate_client(kwargs)
            if self.requires_client_auth and not self.api_client_id:
                raise APIError(400, 'invalid_client',
                               'client authentication required')

        if self.authenticate_token:
            self._authenticate_token(kwargs)

    def _respond(self, response):
        return json.dumps(response)

    def _respond_error(self, error, message):
        return self._respond({'error': error,
                              'error_description': message})

    def _handle_client_authentication(self, auth_method, client_id,
                                      client_secret):
        self.debug('Trying client auth for %s with method %s'
                   % (client_id, auth_method))
        if not client_id:
            self.error('Client authentication without client_id')
            raise APIError(400, 'invalid_client',
                           'client authentication error')

        client = self.cfg.datastore.getClient(client_id)
        if not client:
            self.error('Client authentication with invalid client ID')
            raise APIError(400, 'invalid_client',
                           'client authentication error')

        if client['client_secret_expires_at'] != 0 and \
                client['client_secret_expires_at'] <= int(time.time()):
            self.error('Client authentication with expired secret')
            raise APIError(400, 'invalid_client',
                           'client authentication error')

        if client['token_endpoint_auth_method'] != auth_method:
            self.error('Client authentication with invalid auth method: %s'
                       % auth_method)
            raise APIError(400, 'invalid_client',
                           'client authentication error')

        if not constant_time_string_comparison(client['client_secret'],
                                               client_secret):
            self.error('Client authentication with invalid secret: %s'
                       % client_secret)
            raise APIError(400, 'invalid_client',
                           'client authentication error')

        self.api_client_authenticated = True
        self.api_client_id = client_id
        self.api_client = client

    def _authenticate_client(self, post_args):
        request = cherrypy.serving.request
        self.debug('Trying to authenticate client')
        if 'authorization' in request.headers:
            self.debug('Authorization header found')
            hdr = request.headers['authorization']
            if hdr.startswith('Basic '):
                self.debug('Authorization header is basic')
                hdr = hdr[len('Basic '):]
                try:
                    client_id, client_secret = \
                        base64.b64decode(hdr).split(':', 1)
                except Exception as e:  # pylint: disable=broad-except
                    self.error('Invalid request received: %s' % repr(e))
                    self._respond_error('invalid_request',
                                        'invalid auth header')
                self.debug('Client ID: %s' % client_id)
                self._handle_client_authentication('client_secret_basic',
                                                   client_id,
                                                   client_secret)
            else:
                self.error('Invalid authorization header presented')
                response = cherrypy.serving.response
                response.headers['WWW-Authenticate'] = 'Bearer realm="Ipsilon"'
                raise cherrypy.HTTPError(401, "Unauthorized")
        elif 'client_id' in post_args:
            self.debug('Client id found in post args: %s'
                       % post_args['client_id'])
            self._handle_client_authentication('client_secret_post',
                                               post_args['client_id'],
                                               post_args.get('client_secret',
                                                             ''))
        else:
            self.error('No authorization presented')
            response = cherrypy.serving.response
            response.headers['WWW-Authenticate'] = 'Bearer realm="Ipsilon"'
            raise cherrypy.HTTPError(401, "Unauthorized")
        # FIXME: Perhaps add client_secret_jwt and private_key_jwt as per
        # OpenID Connect Core section 9

    def _handle_token_authentication(self, token):
        token = self.cfg.datastore.lookupToken(token, 'Bearer')
        if not token:
            self.error('Unknown token provided')
            raise APIError(400, 'invalid_token')

        if self.api_client_id:
            if token['client_id'] != self.api_client_id:
                self.error('Authenticated client is not token owner: %s != %s'
                           % (token['client_id'], self.api_client_id))
                raise APIError(400, 'invalid_request')
        else:
            self.api_client = self.cfg.datastore.getClient(token['client_id'])
            if not self.api_client:
                self.error('Token authentication with invalid client ID')
                raise APIError(400, 'invalid_client',
                               'client authentication error')

        if (self.required_scope is not None and
                self.required_scope not in token['scope']):
            self.error('Required %s not in token scopes %s'
                       % (self.required_scope, token['scope']))
            raise APIError(403, 'insufficient_scope')

        self.api_client_id = token['client_id']
        self.api_valid_token = True
        self.api_username = token['username']
        self.api_scopes = token['scope']
        self.api_token = token

    def _authenticate_token(self, post_args):
        request = cherrypy.serving.request
        if 'authorization' in request.headers:
            hdr = request.headers['authorization']
            if hdr.startswith('Bearer '):
                token = hdr[len('Bearer '):]
                self._handle_token_authentication(token)
            else:
                raise APIError(400, 'invalid_request')
        elif 'access_token' in post_args:
            # Bearer token
            token = post_args['access_token']
            self._handle_token_authentication(token)

    def require_scope(self, scope):
        if scope not in self.api_scopes:
            raise APIError(403, 'insufficient_scope')


class Token(APIRequest):
    authenticate_client = True

    def POST(self, *args, **kwargs):
        grant_type = kwargs.get('grant_type', None)

        if grant_type == 'authorization_code':
            # Handle authz code
            code = kwargs.get('code', None)
            redirect_uri = kwargs.get('redirect_uri', None)

            token = self.cfg.datastore.lookupToken(code, 'Authorization')
            if not token:
                self.error('Unknown authz token provided')
                return self._respond_error('invalid_request',
                                           'invalid token')

            if token['client_id'] != self.api_client_id:
                self.error('Authz code owner does not match authenticated ' +
                           'client: %s != %s' % (token['client_id'],
                                                 self.api_client_id))
                return self._respond_error('invalid_request',
                                           'invalid token for client ID')

            if token['redirect_uri'] != redirect_uri:
                self.error('Token redirect URI does not match request: ' +
                           '%s != %s' % (token['redirect_uri'], redirect_uri))
                return self._respond_error('invalid_request',
                                           'redirect_uri does not match')

            new_token = self.cfg.datastore.exchangeAuthorizationCode(code)
            if not new_token:
                self.error('Was unable to exchange for token')
                return self._respond_error('invalid_grant',
                                           'Could not refresh')
            new_token['token_type'] = 'Bearer'

            return self._respond(new_token)

        elif grant_type == 'refresh_token':
            # Handle token refresh
            refresh_token = kwargs.get('refresh_token', None)

            refresh_result = self.cfg.datastore.refreshToken(
                refresh_token,
                self.api_client_id)

            if not refresh_result:
                return self._respond_error('invalid_grant',
                                           'Something went wrong refreshing')

            return self._respond({
                'access_token': refresh_result['access_token'],
                'token_type': 'Bearer',
                'refresh_token': refresh_result['refresh_token'],
                'expires_in': refresh_result['expires_in']})

        else:
            return self._respond_error('unsupported_grant_type',
                                       'unknown grant_type')


class TokenInfo(APIRequest):
    # RFC7662 (Token introspection)
    authenticate_client = True
    requires_client_auth = True

    def POST(self, *args, **kwargs):
        token = kwargs.get('token', None)

        token = self.cfg.datastore.lookupToken(token, None, True)
        if not token:
            # Per spec, if this token is not valid, but the request itself is,
            # we return with an "empty" response
            return self._respond({
                'active': False
            })

        # FIXME: At this moment, we only have Bearer tokens
        token_type = 'Bearer'

        return self._respond({
            'active': int(time.time()) <= int(token['expires_at']),
            'scope': ' '.join(token['scope']),
            'client_id': token['client_id'],
            'username': token['username'],
            'token_type': token_type,
            'exp': token['expires_at'],
            'iat': token['issued_at'],
            'sub': token['username'],
            'aud': token['client_id'],
            'iss': self.cfg.endpoint_url,
        })


class UserInfo(APIRequest):
    authenticate_token = True
    requires_valid_token = True
    required_scope = 'openid'

    def _get_userinfo(self, *args, **kwargs):
        info = self.cfg.datastore.getUserInfo(self.api_token['userinfocode'])
        if not info:
            return self._respond_error('invalid_request',
                                       'No userinfo for token')

        if self.api_client.get('userinfo_signed_response_alg'):
            cherrypy.response.headers.update({
                'Content-Type': 'application/jwt'
            })

            if self.api_client.get('userinfo_signed_response_alg') == 'RS256':
                sig = JWT(header={'alg': 'RS256',
                                  'kid': self.cfg.idp_sig_key_id},
                          claims=info)
            else:
                return self._respond_error(
                    'unsupported_response_type',
                    'Requested signing mech not supported')
            # FIXME: Maybe add other algorithms in the future
            sig.make_signed_token(self.cfg.keyset.get_key(
                self.cfg.idp_sig_key_id))
            # FIXME: Maybe encrypt in the future
            info = sig.serialize(compact=True)

        if isinstance(info, dict):
            info = json.dumps(info)

        return info

    def GET(self, *args, **kwargs):
        return self._get_userinfo(*kwargs, **kwargs)

    def POST(self, *args, **kwargs):
        return self._get_userinfo(*kwargs, **kwargs)
