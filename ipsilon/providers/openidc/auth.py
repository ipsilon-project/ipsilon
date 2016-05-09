# Copyright (C) 2016 Ipsilon project Contributors, for license see COPYING

from ipsilon.util.log import Log
from ipsilon.providers.common import ProviderPageBase
from ipsilon.providers.common import InvalidRequest
from ipsilon.util.policy import Policy
from ipsilon.util.trans import Transaction
from ipsilon.util.security import (generate_random_secure_string,
                                   constant_time_string_comparison)
from ipsilon.util.user import UserSession

from jwcrypto.jwt import JWT
from jwcrypto.jwk import JWK, JWKSet
from jwcrypto.jws import default_allowed_algs as jws_default_allowed_algs

import base64
import cherrypy
import hashlib
import requests
import time
import json
from urlparse import urlparse

URLROOT = 'openidc'


def get_url_hostpart(url):
    try:
        o = urlparse(url)
        return o.hostname
    except:  # pylint: disable=bare-except
        return url


class AuthenticateRequest(ProviderPageBase):

    def __init__(self, site, provider, *args, **kwargs):
        super(AuthenticateRequest, self).__init__(site, provider,
                                                  *args, **kwargs)
        self.trans = None

    def _preop(self, *args, **kwargs):
        try:
            # generate a new id or get current one
            self.trans = Transaction('openidc', **kwargs)
            if (self.trans.cookie and
                    self.trans.cookie.value != self.trans.provider):
                self.debug('Invalid transaction, %s != %s' % (
                           self.trans.cookie.value, self.trans.provider))
        except Exception, e:  # pylint: disable=broad-except
            self.debug('Transaction initialization failed: %s' % repr(e))
            raise cherrypy.HTTPError(400, 'Invalid transaction id')

    def pre_GET(self, *args, **kwargs):
        self._preop(*args, **kwargs)

    def pre_POST(self, *args, **kwargs):
        self._preop(*args, **kwargs)

    # get attributes, and apply policy mapping and filtering
    def _source_attributes(self, session):
        policy = Policy(self.cfg.default_attribute_mapping,
                        self.cfg.default_allowed_attributes)
        userattrs = session.get_user_attrs()
        mappedattrs, _ = policy.map_attributes(userattrs)
        attributes = policy.filter_attributes(mappedattrs)
        self.debug('Filterd attributes: %s' % repr(attributes))
        return attributes

    def _respond(self, request, contents):
        url = request['redirect_uri']
        response_mode = request.get('response_mode', None)
        response_type = request.get('response_type', [])
        if 'none' in response_type:
            response_mode = 'none'
            self.debug('none response_type, using none response_mode')
        elif 'id_token' in response_type or 'token' in response_type:
            if response_mode in [None, 'query']:
                # If no response_mode or query response_mode is selected,
                # fall back to the default for id_token or token requests,
                # which is fragment encoding. The query override is because
                # the specifications specify that with id_token or token,
                # query MUST NOT be used.
                response_mode = 'fragment'
                self.debug('id_token requesed, fragment response_mode forced')
        elif not response_mode:
            # We still have no response_mode, fall back to query
            # This also happens in case we were unable to parse the request,
            # and as such were unable to get the response_mode the client
            # preferred
            response_mode = 'query'
            self.debug('Using default query response mode')

        # If the client sent a state, we need to pass that back
        if 'state' in request:
            contents['state'] = request['state']

        # Build a response-string, which is sent with either query, form
        # or fragment responses
        if response_mode in ['query', 'fragment']:
            data = ['%s=%s' % (key, contents[key]) for key in contents.keys()]

            separator = '?'
            if response_mode == 'fragment':
                separator = '#'
            if separator not in url:
                url += separator
            else:
                url += '&'

            url += '&'.join(data)

        if response_mode in ['query', 'fragment', 'none']:
            raise cherrypy.HTTPRedirect(url)
        elif response_mode == 'form_post':
            context = {
                "title": "Continue",
                "redirect_url": url,
                "response_info": contents
            }
            return self._template(URLROOT + '/form_response.html', **context)
        else:
            raise InvalidRequest('Invalid response_mode requested')

    def _respond_error(self, request, error, message):
        if request.get('redirect_uri') is None:
            raise InvalidRequest('Request is missing redirct_uri')

        return self._respond(request, {'error': error,
                                       'error_description': message})


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


class Authorization(AuthenticateRequest):

    def start_authz(self, arguments):
        request_data = {
            'scope': [],
            'response_type': [],
            'client_id': None,
            'redirect_uri': None,
            'state': None,
            'response_mode': None,
            'nonce': None,
            'display': None,
            'prompt': [],
            'max_age': None,
            'ui_locales': None,
            'id_token_hint': None,
            'login_hint': None,
            'acr_values': None,
            'claims': '{}'
        }

        # Get the request
        # Step 1: get the get query arguments
        for data in request_data.keys():
            if arguments.get(data, None):
                request_data[data] = arguments[data]

        # This is a workaround for python not understanding the splits we
        # do later
        if request_data['prompt'] == []:
            request_data['prompt'] = None

        for required_arg in ['scope',
                             'response_type',
                             'client_id']:
            if request_data[required_arg] is None or \
                    len(request_data[required_arg]) == 0:
                return self._respond_error(request_data,
                                           'invalid_request',
                                           'missing required argument %s' %
                                           required_arg)

        client = self.cfg.datastore.getClient(request_data['client_id'])
        if not client:
            return self._respond_error(request_data,
                                       'unauthorized_client',
                                       'Unknown client ID')

        request_data['response_type'] = request_data.get('response_type',
                                                         '').split(' ')
        for rtype in request_data['response_type']:
            if rtype not in ['id_token', 'token', 'code']:
                return self._respond_error(request_data,
                                           'unsupported_response_type',
                                           'response type %s is not supported'
                                           % rtype)

        if request_data['response_type'] != ['code'] and \
                not request_data['nonce']:
            return self._respond_error(request_data,
                                       'invalid_request',
                                       'nonce missing in non-code flow')

        # Step 2: get any provided request or request_uri
        if 'request' in arguments or 'request_uri' in arguments:
            # This is a JWT-encoded request
            if 'request' in arguments and 'request_uri' in arguments:
                return self._respond_error(request_data,
                                           'invalid_request',
                                           'both request and request_uri ' +
                                           'provided')

            if 'request' in arguments:
                jwt_object = arguments['request']
            else:
                try:
                    # FIXME: MAY cache this at client registration time and
                    # cache permanently until client registration is changed.
                    jwt_object = requests.get(arguments['request_uri']).text
                except Exception as ex:  # pylint: disable=broad-except
                    self.debug('Unable to get request: %s' % ex)
                    return self._respond_error(request_data,
                                               'invalid_request',
                                               'unable to parse request_uri')

            jwt_request = None
            try:
                # FIXME: Implement decryption
                decoded = JWT(jwt=jwt_object)
                if 'request_object_signing_alg' in client:
                    # Client told us we need to check signature
                    if decoded.token.jose_header['alg'] != \
                            client['request_object_signing_alg']:
                        raise Exception('Invalid algorithm used: %s'
                                        % decoded.token.jose_header['alg'])

                    if client['request_object_signing_alg'] == 'none':
                        jwt_request = json.loads(
                            decoded.token.objects['payload'])
                    else:
                        keyset = None
                        if 'jkws' in client:
                            keys = json.loads(client['jkws'])
                        else:
                            keys = requests.get(client['jwks_uri']).json()
                        keyset = JWKSet()
                        for key in keys['keys']:
                            keyset.add(JWK(**key))
                        key = keyset.get_key(decoded.token.jose_header['kid'])
                        decoded = JWT(jwt=jwt_object, key=key)
                        jwt_request = json.loads(decoded.claims)

            except Exception as ex:  # pylint: disable=broad-except
                self.debug('Unable to parse request: %s' % ex)
                return self._respond_error(request_data,
                                           'invalid_request',
                                           'unable to parse request')

            if 'response_type' in jwt_request:
                jwt_request['response_type'] = \
                    jwt_request['response_type'].split(' ')
                if jwt_request['response_type'] != \
                        request_data['response_type']:
                    return self._respond_error(request_data,
                                               'invalid_request',
                                               'response_type does not match')

            if 'client_id' in jwt_request:
                if jwt_request['client_id'] != request_data['client_id']:
                    return self._respond_error(request_data,
                                               'invalid_request',
                                               'client_id does not match')

            for data in request_data.keys():
                if data in jwt_request:
                    request_data[data] = jwt_request[data]

        # Split these options since they are space-separated lists
        for to_split in ['prompt',
                         'ui_locales',
                         'acr_values',
                         'scope']:
            if request_data[to_split] is not None:
                # We know better than pylint in this regard
                # pylint: disable=no-member
                request_data[to_split] = request_data[to_split].split(' ')
            else:
                request_data[to_split] = []

        # Start checking the request
        if request_data['redirect_uri'] is None:
            if len(client['redirect_uris']) != 1:
                return self._respond_error(request_data,
                                           'invalid_request',
                                           'missing redirect_uri')
            else:
                request_data['redirect_uri'] = client['redirect_uris'][0]

        for scope in request_data['scope']:
            if scope not in self.cfg.supported_scopes:
                return self._respond_error(request_data,
                                           'invalid_scope',
                                           'unknown scope %s requested' %
                                           scope)

        for response_type in request_data['response_type']:
            if response_type not in ['code', 'id_token', 'token']:
                return self._respond_error(request_data,
                                           'unsupported_response_type',
                                           'response_type %s is unknown'
                                           % response_type)

        if request_data['redirect_uri'] not in client['redirect_uris']:
            raise InvalidRequest('Invalid redirect_uri')

        # Build the "claims" values from scopes
        try:
            request_data['claims'] = json.loads(request_data['claims'])
        except Exception, ex:  # pylint: disable=broad-except
            return self._respond_error(request_data,
                                       'invalid_request',
                                       'claims malformed: %s' % ex)
        if 'userinfo' not in request_data['claims']:
            request_data['claims']['userinfo'] = {}
        if 'id_token' not in request_data['claims']:
            request_data['claims']['id_token'] = {}

        scopes_to_claim = {
            'profile': [
                'name', 'family_name', 'given_name', 'middle_name', 'nickname',
                'preferred_username', 'profile', 'picture', 'website',
                'gender', 'birthdate', 'zoneinfo', 'locale', 'updated_at'
            ],
            'email': ['email', 'email_verified'],
            'address': ['address'],
            'phone': ['phone_number', 'phone_number_verified']
        }
        for scope in scopes_to_claim:
            if scope in request_data['scope']:
                for claim in scopes_to_claim[scope]:
                    if claim not in request_data['claims']:
                        # pylint: disable=invalid-sequence-index
                        request_data['claims']['userinfo'][claim] = None

        # Store data so we can continue with the request
        us = UserSession()
        user = us.get_user()

        returl = '%s/%s/Continue?%s' % (
            self.basepath, URLROOT, self.trans.get_GET_arg())
        data = {'login_target': client.get('client_name', None),
                'login_return': returl,
                'openidc_stage': 'continue',
                'openidc_request': json.dumps(request_data)}

        if request_data['login_hint']:
            data['login_username'] = request_data['login_hint']

        if not data['login_target']:
            data['login_target'] = get_url_hostpart(
                request_data['redirect_uri'])

        # Decide what to do with the request
        if request_data['max_age'] is None:
            request_data['max_age'] = client.get('default_max_age', None)

        needs_auth = True
        if not user.is_anonymous:
            if request_data['max_age'] is None:
                needs_auth = False
            else:
                auth_time = us.get_user_attrs()['_auth_time']
                needs_auth = ((int(auth_time) +
                              int(request_data['max_age'])) <=
                              int(time.time()))

        if needs_auth or 'login' in request_data['prompt']:
            if 'none' in request_data['prompt']:
                # We were asked not to provide a UI. Answer with false.
                return self._respond_error(request_data,
                                           'login_required',
                                           'user interface required')

            # Either the user wasn't logged in, or we were explicitly
            # asked to re-auth them. Let's do so!
            us.logout(user)

            # Let the user go to auth
            self.trans.store(data)
            redirect = '%s/login?%s' % (self.basepath,
                                        self.trans.get_GET_arg())
            self.debug('Redirecting: %s' % redirect)
            raise cherrypy.HTTPRedirect(redirect)

        self.trans.store(data)
        # The user was already signed on, and no request to re-assert its
        # identity. Let's forward directly to /Continue/
        self.debug('Redirecting: %s' % returl)
        raise cherrypy.HTTPRedirect(returl)

    def GET(self, *args, **kwargs):
        return self.start_authz(kwargs)

    def POST(self, *args, **kwargs):
        return self.start_authz(kwargs)


class Continue(AuthenticateRequest):

    def _respond_success(self, request, client, user, userinfo):
        # Answer the current request with a successful response.
        response = {}

        if client['subject_type'] == 'public':
            userinfo['sub'] = user.name
        else:
            h = hashlib.sha256()
            if 'sector_identifier_uri' in client:
                domain = get_url_hostpart(
                    client['sector_identifier_uri'])
            else:
                # We are guaranteed that we either have a sector_identifier_uri
                # or that the hostpart of all redirect_uris are equal
                domain = get_url_hostpart(client['redirect_uris'][0])
            h.update(domain)
            h.update(user.name)
            h.update(self.cfg.idp_subject_salt)
            userinfo['sub'] = h.hexdigest()

        claims_userinfo = {}
        for requested_claim in request['claims']['userinfo']:
            if requested_claim in userinfo:
                claims_userinfo[requested_claim] = userinfo[requested_claim]
        claims_userinfo['sub'] = userinfo['sub']

        userinfocode = None
        if 'openid' in request['scope']:
            userinfocode = self.cfg.datastore.storeUserInfo(claims_userinfo)

        if 'token' in request['response_type']:
            # Asked to return token in authz response
            # Flows: Hybrid and Implicit
            token = self.cfg.datastore.issueToken(
                request['client_id'],
                user.name,
                request['scope'],
                False,
                userinfocode)
            del token['token_id']
            response['access_token'] = token['access_token']
            response['token_type'] = 'Bearer'
            response['expires_in'] = token['expires_in']

        if 'code' in request['response_type']:
            # Asked to return authorization code
            # Flows: Authorization code and Hybrid
            response['code'] = self.cfg.datastore.issueAuthorizationCode(
                request['client_id'],
                user.name,
                request['scope'],
                userinfo,
                request['redirect_uri'],
                userinfocode)

        if 'openid' in request['scope']:
            id_token = {}

            # Build the id_token
            for requested_claim in request['claims']['id_token']:
                if requested_claim in userinfo:
                    id_token[requested_claim] = userinfo[requested_claim]

            id_token['sub'] = userinfo['sub']
            id_token['iss'] = self.cfg.endpoint_url
            id_token['aud'] = request['client_id']
            id_token['exp'] = int(time.time()) + 600
            id_token['iat'] = int(time.time())
            id_token['auth_time'] = userinfo['_auth_time']
            if 'nonce' in request:
                id_token['nonce'] = request['nonce']
            id_token['acr'] = '0'
            id_token['amr'] = json.dumps([])
            id_token['azp'] = request['client_id']

            if 'code' in response:
                # Add c_hash
                id_token['c_hash'] = self._calc_hash(response['code'])

            if 'access_token' in response:
                # Add at_hash
                id_token['at_hash'] = self._calc_hash(response['access_token'])

            sig = JWT(header={'alg': 'RS256',
                              'kid': self.cfg.idp_sig_key_id},
                      claims=id_token)
            # FIXME: Maybe add other algorithms in the future
            sig.make_signed_token(self.cfg.keyset.get_key(
                self.cfg.idp_sig_key_id))
            # FIXME: Maybe encrypt in the future
            signed_id_token = sig.serialize(compact=True)

            if 'code' in response:
                self.cfg.datastore.storeAuthorizationIDToken(response['code'],
                                                             signed_id_token)

            if 'id_token' in request['response_type']:
                response['id_token'] = signed_id_token

        return self._respond(request, response)

    def _calc_hash(self, msg):
        h = hashlib.sha256(msg.encode()).digest()
        return base64.urlsafe_b64encode(h[:16]).rstrip(b'=').decode()

    def _perform_continue(self, *args, **kwargs):
        us = UserSession()
        user = us.get_user()

        if user.is_anonymous:
            raise InvalidRequest('User not authenticated at continue')

        transdata = self.trans.retrieve()
        stage = transdata.get('openidc_stage', None)
        request_data = transdata.get('openidc_request', None)
        if stage not in ['continue', 'consent'] or request_data is None:
            raise InvalidRequest('Invalid stage or no request')

        # Since we have openidc_stage continue or consent, request is sane
        try:
            request_data = json.loads(request_data)
        except:
            raise InvalidRequest('Unable to re-parse stored request')

        client = self.cfg.datastore.getClient(request_data['client_id'])
        if not client:
            return self._respond_error(request_data,
                                       'unauthorized_client',
                                       'Unknown client ID')

        userattrs = self._source_attributes(us)
        if client['ipsilon_internal']['trusted']:
            # No consent needed, approve
            self.debug('Client trusted, no consent needed')
            return self._respond_success(request_data,
                                         client,
                                         user,
                                         userattrs)

        if 'none' in request_data['prompt']:
            # We were asked to not show any UI
            return self._respond_error(request_data,
                                       'consent_required',
                                       'user interface required')

        # Now ask consent
        if 'form_filled' in kwargs and stage == 'consent':
            # The user has been shown the form, let's process his choice
            if 'decided_allow' in kwargs:
                # User allowed the request
                return self._respond_success(request_data,
                                             client,
                                             user,
                                             userattrs)

            else:
                # User denied consent
                self.debug('User denied consent')
                return self._respond_error(request_data,
                                           'access_denied',
                                           'user denied consent')
        else:
            # The user was not shown the form yet, let's
            data = {'openidc_stage': 'consent',
                    'openidc_request': json.dumps(request_data)}
            self.trans.store(data)

            userattrs = self._source_attributes(us)
            claim_requests = {}
            for claimtype in request_data['claims']:
                for claim in request_data['claims'][claimtype]:
                    if claim in userattrs:
                        essential = False
                        if isinstance(
                                request_data['claims'][claimtype][claim],
                                dict):
                            essential = \
                                request_data['claims'][claimtype][claim].get(
                                    'essential', False)

                        claim_requests[claim] = {
                            'display_name': self.cfg.mapping.display_name(
                                claim),
                            'value': userattrs[claim],
                            'essential': essential
                        }

            scopes = {}
            # Add extension data
            for n, e in self.cfg.extensions.available().items():
                data = e.get_display_data(request_data['scope'])
                self.debug('%s returned %s' % (n, repr(data)))
                if len(data) > 0:
                    scopes[e.get_display_name()] = data

            client_params = {
                'name': client.get('client_name', None),
                'logo': client.get('logo_uri', None),
                'homepage': client.get('client_uri', None),
                'policy': client.get('policy_uri', None),
                'tos': client.get('tos_uri', None)
            }

            if not client_params['name']:
                client_params['name'] = get_url_hostpart(
                    request_data['redirect_uri'])

            context = {
                "title": 'Consent',
                "action": '%s/%s/Continue' % (self.basepath, URLROOT),
                "client": client_params,
                "claim_requests": claim_requests,
                "scopes": scopes,
                "username": user.name,
            }
            context.update(dict((self.trans.get_POST_tuple(),)))
            return self._template(URLROOT + '/consent_form.html', **context)

    def GET(self, *args, **kwargs):
        # We do not pass kwargs in the case of GET, since there
        # will be no arguments passed to this endpoint by GET
        # that we need to process
        return self._perform_continue(*args)

    def POST(self, *args, **kwargs):
        return self._perform_continue(*args, form_filled=True, **kwargs)


class Registration(APIRequest):

    def POST(self, *args, **kwargs):
        try:
            client_metadata = json.loads(cherrypy.request.rfile.read())
        except:
            raise APIError(400, 'invalid_client_metadata',
                           'unable to parse metadata')
        self.debug('Received client registration request: %s'
                   % client_metadata)

        # Fill in defaults for optional arguments
        client_metadata['response_types'] = client_metadata.get(
            'response_types', ['code'])
        client_metadata['grant_types'] = client_metadata.get(
            'grant_types', ['authorization_code'])
        client_metadata['application_type'] = client_metadata.get(
            'application_type', 'web')
        client_metadata['contacts'] = client_metadata.get('contacts', [])
        client_metadata['subject_type'] = client_metadata.get('subject_type',
                                                              'pairwise')
        client_metadata['id_token_signed_response_alg'] = client_metadata.get(
            'id_token_signed_response_alg', 'RS256')
        client_metadata['token_endpoint_auth_method'] = client_metadata.get(
            'token_endpoint_auth_method', 'client_secret_basic')
        client_metadata['require_auth_time'] = client_metadata.get(
            'require_auth_time', False)

        # Check the client metadata received
        if 'redirect_uris' not in client_metadata:
            raise APIError(400, 'invalid_client_metadata',
                           'missing redirect_uris')

        if client_metadata['application_type'] not in ['web', 'native']:
            raise APIError(400, 'invalid_client_metadata',
                           'application_type invalid')

        for redirect_uri in client_metadata['redirect_uris']:
            if '#' in redirect_uri:
                raise APIError(400, 'invalid_redirect_uri',
                               'redirect_uri contains fragment')

            if client_metadata['application_type'] == 'web':
                # In this case, it must be https:// and not https://localhost
                if (not redirect_uri.startswith('https://') or
                        redirect_uri.startswith('https://localhost')):
                    raise APIError(400, 'invalid_redirect_uri',
                                   'redirect_uri %s not valid' % redirect_uri)

            elif client_metadata['application_type'] == 'native':
                # In this case, it must be http://localhost, or something
                # that is not http:// or https://
                if (redirect_uri.startswith('https://') or
                        (redirect_uri.startswith('http://') and
                         not redirect_uri.startswith('http://localhost'))):
                    raise APIError(400, 'invalid_redirect_uri',
                                   'redirect_uri %s not valid' % redirect_uri)

        if 'initiate_login_uri' in client_metadata:
            if not client_metadata['initiate_login_uri'].startswith(
                    'https://'):
                raise APIError(400, 'invalid_client_metadata',
                               'initiate_login_uri must be https')

        if 'sector_identifier_uri' not in client_metadata:
            hostname = None
            for redir_uri in client_metadata['redirect_uris']:
                cur_host = get_url_hostpart(redir_uri)
                if not cur_host:
                    raise APIError(400, 'invalid_client_metadata',
                                   'Unable to parse hostname from ' +
                                   'redirect_uri %s' % redir_uri)
                if hostname is not None and cur_host != hostname:
                    raise APIError(400, 'invalid_client_metadata',
                                   'Multiple redirect_uri hostnames without ' +
                                   'sector_identifier_uri')
                hostname = cur_host
        else:
            if not client_metadata['sector_identifier_uri'].startswith(
                    'https://'):
                raise APIError(400, 'invalid_client_metadata',
                               'sector_identifier_uri must be https')

            try:
                resp = requests.get(client_metadata['sector_identifier_uri'])
                resp = resp.json()
                for redirect_uri in client_metadata['redirect_uris']:
                    if redirect_uri not in resp:
                        raise APIError(400, 'invalid_client_metadata',
                                       'redirect_uri %s not in ' +
                                       'sector_identifier_uri document' %
                                       redirect_uri)
            except Exception as ex:
                self.debug('Unable to process sector_identifier_uri: %s' %
                           ex)
                raise APIError(400, 'invalid_client_metadata',
                               'unable to process sector_identifier_uri')

        if 'code' in client_metadata['response_types']:
            if 'authorization_code' not in client_metadata['grant_types']:
                raise APIError(400, 'invalid_client_metadata',
                               'authorization_code missing with code')

        if ('token' in client_metadata['response_types'] or
                'id_token' in client_metadata['response_types']):
            if 'implicit' not in client_metadata['grant_types']:
                raise APIError(400, 'invalid_client_metadata',
                               'implicit missing with token or id_token')

        if 'jwks' in client_metadata and 'jwks_uri' in client_metadata:
            raise APIError(400, 'invalid_client_metadata',
                           'both jwks and jwks_uri provided')

        # If all checks pass, generate client ID and secret
        client_metadata['client_secret'] = \
            generate_random_secure_string()
        client_metadata['client_secret_expires_at'] = 0  # FIXME: Expire?
        client_metadata['client_id_issued_at'] = int(time.time())

        # Store some internal data
        client_metadata['ipsilon_internal'] = {
            'trusted': False
        }

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

        if 'userinfo_signed_response_alg' in self.api_client:
            cherrypy.response.headers.update({
                'Content-Type': 'application/jwt'
            })

            sig = JWT(header={'alg': 'RS256',
                              'kid': self.cfg.idp_sig_key_id},
                      claims=info)
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


class OpenIDC(ProviderPageBase):

    def __init__(self, *args, **kwargs):
        super(OpenIDC, self).__init__(*args, **kwargs)
        self.Authorization = Authorization(*args, **kwargs)
        self.Continue = Continue(*args, **kwargs)
        self.Token = Token(*args, **kwargs)
        self.TokenInfo = TokenInfo(*args, **kwargs)
        self.Registration = Registration(*args, **kwargs)
        self.UserInfo = UserInfo(*args, **kwargs)

    def wellknown_openid_configuration(self):
        cherrypy.response.headers.update({
            'Content-Type': 'application/json'
        })

        configuration = {
            'issuer': self.cfg.endpoint_url,
            'authorization_endpoint': '%s%s' % (self.cfg.endpoint_url,
                                                'Authorization'),
            'token_endpoint': '%s%s' % (self.cfg.endpoint_url,
                                        'Token'),
            'userinfo_endpoint': '%s%s' % (self.cfg.endpoint_url,
                                           'UserInfo'),
            'jwks_uri': '%s%s' % (self.cfg.endpoint_url,
                                  'Jwks'),
            'registration_endpoint': '%s%s' % (self.cfg.endpoint_url,
                                               'Registration'),
            'scopes_supported': self.cfg.supported_scopes,
            'response_types_supported': ['code', 'id_token' 'token',
                                         'token id_token'],
            'response_modes_supported': ['query', 'fragment', 'form_post',
                                         'none'],
            'grant_types_supported': ['authorization_code', 'implicit',
                                      'refresh_token'],
            'acr_values_supported': ['0'],
            'subject_types_supported': ['pairwise', 'public'],
            # FIXME: At some point, we might want to support all the algorithms
            # that jwcrypto has support for
            'id_token_signing_alg_values_supported': ['RS256'],
            'id_token_encryption_alg_values_supported': [],
            'id_token_encryption_enc_values_supported': [],
            'userinfo_signing_alg_values_supported': ['RS256'],
            'userinfo_encryption_alg_values_supported': [],
            'userinfo_encryption_enc_values_supported': [],
            'request_object_signing_alg_values_supported':
                jws_default_allowed_algs + ['none'],
            'request_object_encryption_alg_values_supported': [],
            'request_object_encryption_enc_values_supported': [],
            'token_endpoint_auth_methods_supported': [
                'client_secret_basic',
                'client_secret_post'
            ],
            'token_endpoint_auth_signing_alg_values_supported': ['RS256'],
            'display_values_supported': ['page', 'popup'],
            'claim_types_supported': ['normal'],
            'claims_supported': [
                'sub', 'name', 'given_name', 'family_name', 'middle_name',
                'nickname', 'preferred_username', 'profile', 'picture',
                'website', 'email', 'email_verified', 'gender', 'birthdate',
                'zoneinfo', 'locale', 'phone_number', 'phone_number_verified',
                'address', 'updated_at'
            ],
            'service_documentation': self.cfg.documentation_url,
            # 'claims_locales_supported': [],
            'ui_locales_supported': ['en'],
            'claims_parameter_supported': True,
            'request_parameter_supported': True,
            'request_uri_parameter_supported': True,
            'require_request_uri_registration': False,
            'op_policy_uri': self.cfg.policy_url,
            'op_tos_uri': self.cfg.tos_url,
        }

        return json.dumps(configuration)
    wellknown_openid_configuration.public_function = True

    def Jwks(self):
        cherrypy.response.headers.update({
            'Content-Type': 'application/json'
        })

        # Sent to jwcrypto as https://github.com/latchset/jwcrypto/pull/20
        keys = []
        for key in self.cfg.keyset:
            keys.append(json.loads(key.export_public()))
        return json.dumps({'keys': keys})
    Jwks.public_function = True

    def __call__(self, *args, **kwargs):
        # We need to have this because it's impossible to have a function
        # called .well-known
        if len(args) == 2 and args == ('.well-known', 'openid-configuration'):
            args = ('wellknown_openid_configuration', )

        return super(OpenIDC, self).__call__(*args, **kwargs)
