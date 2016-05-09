# Copyright (C) 2016 Ipsilon project Contributors, for license see COPYING

from ipsilon.util.security import (generate_random_secure_string,
                                   constant_time_string_comparison)
from ipsilon.util.data import Store, UNIQUE_DATA_TABLE

import json
import time


class OpenIDCStore(Store):
    def __init__(self, database_url):
        Store.__init__(self, database_url=database_url)

    def registerDynamicClient(self, client):
        data = {}

        for key in client:
            data[key] = json.dumps(client[key])

        client_id = self.new_unique_data('client', data)

        # Prepend client ID with D- to indicate that this is a dynamic client
        return 'D-%s' % client_id

    def registerStaticClient(self, client):
        # TODO: Implement static client

        client_id = None

        # Prepend client ID with S- to indicate that this is a static client
        return 'S-%s' % client_id

    def getClient(self, client_id):
        if client_id.startswith('D-'):
            # This is a dynamically registered client
            client_id = client_id[2:]
            data = self.get_unique_data('client', client_id)
        elif client_id.startswith('S-'):
            # This is a statically configured client
            client_id = client_id[2:]
            # TODO: Get the configured client data
            return None
        else:
            # No idea what this is
            self.debug('Invalid client ID request: %s' % client_id)
            return None

        if len(data) < 1:
            return None

        datum = data[client_id]

        for key in datum:
            datum[key] = json.loads(datum[key])

        return datum

    def lookupToken(self, token, expected_type, return_expired=False):
        if '_' not in token:
            return None

        checkfield = 'security_check'
        if expected_type == 'Refresh' and token.startswith('R_'):
            checkfield = 'refresh_security_check'
            token = token[len('R_'):]

        token_id, security_check = token.split('_', 1)

        data = self.get_unique_data('token', token_id)

        if len(data) < 1:
            return None

        datum = data[token_id]

        if not constant_time_string_comparison(security_check,
                                               datum[checkfield]):
            return None

        if not return_expired and \
                datum['expires_at'] <= int(time.time()):
            return None

        if expected_type and expected_type != 'Refresh' and \
                datum['type'] != expected_type:
            return None

        datum['scope'] = json.loads(datum['scope'])
        datum['token_id'] = token_id

        return datum

    def storeAuthorizationIDToken(self, authz_code, signed_id_token):
        token = self.lookupToken(authz_code, 'Authorization')
        if not token:
            return None
        token['id_token'] = signed_id_token
        self.update_token(token)

    def update_token(self, token):
        token_id = token['token_id']
        del token['token_id']
        token['scope'] = json.dumps(token['scope'])

        self.save_unique_data('token', {token_id: token})

    def refreshToken(self, refresh_token, client_id):
        token = self.lookupToken(refresh_token, 'Refresh', True)

        if not token:
            return None

        if not constant_time_string_comparison(token['client_id'],
                                               client_id):
            return None

        if token['type'] != 'Bearer':
            # Only Bearer tokens are supported
            return None

        if not token['refreshable']:
            return None

        if token['refreshable_until'] and \
                token['refreshable_until'] >= int(time.time()):
            return None

        token_security_check = generate_random_secure_string()
        refresh_security_check = generate_random_secure_string(128)
        expires_in = 3600
        # TODO: Figure out values for this
        refreshable_until = None

        token['security_check'] = token_security_check
        token['refresh_security_check'] = refresh_security_check
        token['expires_at'] = int(time.time()) + expires_in
        token['refreshable_until'] = refreshable_until

        self.update_token(token)

        token = '%s_%s' % (token['token_id'], token_security_check)
        refresh_token = 'R_%s_%s' % (token['token_id'], refresh_security_check)

        return {
            'access_token': token,
            'refresh_token': refresh_token,
            'expires_in': expires_in
        }

    def issueToken(self, client_id, username, scope, issue_refresh,
                   userinfocode):
        token_security_check = generate_random_secure_string()

        expires_in = 3600

        token = {
            'type': 'Bearer',
            'security_check': token_security_check,
            'client_id': client_id,
            'username': username,
            'scope': json.dumps(scope),
            'expires_at': int(time.time()) + expires_in,
            'issued_at': int(time.time()),
            'refreshable': False,
            'userinfocode': userinfocode
        }

        if issue_refresh:
            token['refreshable'] = True
            # TODO: Figure out time for this
            token['refreshable_until'] = None
            token['refresh_security_check'] = \
                generate_random_secure_string(128)

        token_id = self.new_unique_data('token', token)

        # The refresh token also has a prefix of R_ to make it distinguishable
        if issue_refresh:
            refresh_token = 'R_%s_%s' % (token_id,
                                         token['refresh_security_check'])
        else:
            refresh_token = None

        # The returned token is the token ID with appended to it the security
        # check value.
        # The token ID is used to lookup the token in the database, and the
        # security check value is used to make the string slightly more
        # random
        token = '%s_%s' % (token_id, token_security_check)

        return {
            "token_id": token_id,
            'access_token': token,
            'refresh_token': refresh_token,
            'expires_in': expires_in,
        }

    def invalidateToken(self, token):
        self.del_unique_data('token', token)

    def storeUserInfo(self, userinfo):
        to_store = {}
        for key in userinfo:
            to_store[key] = json.dumps(userinfo[key])

        return self.new_unique_data('userinfo', to_store)

    def getUserInfo(self, userinfocode):
        data = self.get_unique_data('userinfo', userinfocode)
        if len(data) < 1:
            return None

        data = data[userinfocode]

        userinfo = {}
        for key in data:
            userinfo[key] = json.loads(data[key])
        return userinfo

    def exchangeAuthorizationCode(self, authz_code):
        token = self.lookupToken(authz_code, 'Authorization')
        if not token:
            return None

        if 'issued_token' in token:
            # This authorization code was already used before... We don't know
            # whether this is a malfunctional client or if the authorization
            # code got stolen, so let's just revoke the old key and refuse this
            # request.
            self.invalidateToken(token['issued_token'])
            return None

        new_token = self.issueToken(token['client_id'], token['username'],
                                    token['scope'], True,
                                    token['userinfocode'])
        if not new_token:
            return None

        if 'id_token' in token:
            new_token['id_token'] = token['id_token']

        token['issued_token'] = new_token['token_id']
        del new_token['token_id']

        self.update_token(token)

        return new_token

    def issueAuthorizationCode(self, client_id, username, scope, userinfo,
                               redirect_uri, userinfocode):
        token_security_check = generate_random_secure_string()

        expires_in = 600

        token = {
            'type': 'Authorization',
            'security_check': token_security_check,
            'client_id': client_id,
            'username': username,
            'scope': json.dumps(scope),
            'expires_at': int(time.time()) + expires_in,
            'userinfocode': userinfocode,
            'redirect_uri': redirect_uri
        }

        token_id = self.new_unique_data('token', token)

        # The returned token is the token ID with appended to it the security
        # check value.
        # The token ID is used to lookup the token in the database, and the
        # security check value is used to make the string slightly more
        # random
        token = '%s_%s' % (token_id, token_security_check)

        return token

    def _cleanup(self):
        # TODO: Clean up any tokens with expiry <= time.time()
        return 0

    def _initialize_schema(self):
        q = self._query(self._db, 'client', UNIQUE_DATA_TABLE,
                        trans=False)
        q.create()
        q._con.close()  # pylint: disable=protected-access
        q = self._query(self._db, 'token', UNIQUE_DATA_TABLE,
                        trans=False)
        q.create()
        q._con.close()  # pylint: disable=protected-access
        q = self._query(self._db, 'userinfo', UNIQUE_DATA_TABLE,
                        trans=False)
        q.create()
        q._con.close()  # pylint: disable=protected-access

    def _upgrade_schema(self, old_version):
        raise NotImplementedError()
