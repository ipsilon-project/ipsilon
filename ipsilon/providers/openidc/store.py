# Copyright (C) 2016 Ipsilon project Contributors, for license see COPYING

from ipsilon.util.security import (generate_random_secure_string,
                                   constant_time_string_comparison)
from ipsilon.util.data import Store, UNIQUE_DATA_TABLE, OPTIONS_TABLE

from uuid import uuid4
import json
import time


# This is a different store, since this can be a configuration file if the
# static OpenIDC clients are stored in a configuration file.
class OpenIDCStaticStore(Store):
    _should_cleanup = False

    def __init__(self, database_url):
        Store.__init__(self, database_url=database_url)

    def _initialize_schema(self):
        q = self._query(self._db, 'client', OPTIONS_TABLE,
                        trans=False)
        q.create()
        q._con.close()  # pylint: disable=protected-access

    def _upgrade_schema(self, old_version):
        raise NotImplementedError()


class OpenIDCStore(Store):
    def __init__(self, database_url, static_store):
        Store.__init__(self, database_url=database_url)
        self.static_store = static_store

    def registerDynamicClient(self, client):
        data = {}

        for key in client:
            data[key] = json.dumps(client[key])

        client_id = self.new_unique_data('client', data)

        # Prepend client ID with D- to indicate that this is a dynamic client
        return 'D-%s' % client_id

    def registerStaticClient(self, client_id, client):
        if not client_id:
            client_id = uuid4().hex

        data = {}
        for key in client:
            data[key] = json.dumps(client[key])

        self.static_store.save_options('client', client_id, data)

        return client_id

    def updateClient(self, client_id, client):
        if 'type' in client['ipsilon_internal']:
            del client['ipsilon_internal']['type']
        if 'client_id' in client['ipsilon_internal']:
            del client['ipsilon_internal']['client_id']

        info = {}
        for key in client:
            info[key] = json.dumps(client[key])

        if client_id.startswith('D-'):
            # This is a dynamically registered client
            client_id = client_id[2:]
            self.save_unique_data('client', {client_id: info})
        else:
            # This is a statically configured client
            self.static_store.save_options('client', client_id, info)

    def getDynamicClients(self):
        clients = {}
        results = self.get_unique_data('client')
        for cid in results:
            info = {}
            for key in results[cid]:
                info[key] = json.loads(results[cid][key])

            info['ipsilon_internal']['type'] = 'dynamic'
            info['ipsilon_internal']['client_id'] = 'D-%s' % cid
            clients['D-%s' % cid] = info
        return clients

    def getStaticClients(self):
        clients = {}
        results = self.static_store.load_options('client')
        for cid in results:
            info = {}
            for key in results[cid]:
                info[key] = json.loads(results[cid][key])

            info['ipsilon_internal']['type'] = 'static'
            info['ipsilon_internal']['client_id'] = cid
            clients[cid] = info
        return clients

    def getClient(self, client_id):
        if client_id.startswith('D-'):
            # This is a dynamically registered client
            ctype = 'dynamic'
            data = self.get_unique_data('client', client_id[2:])
        else:
            # This is a statically configured client
            ctype = 'static'
            data = self.static_store.load_options('client', client_id)

        if len(data) < 1:
            return None
        elif len(data) == 1:
            datum = data[client_id[2:]]
        else:
            datum = data

        for key in datum:
            datum[key] = json.loads(datum[key])

        datum['ipsilon_internal']['type'] = ctype
        datum['ipsilon_internal']['client_id'] = client_id

        return datum

    def deleteClient(self, client_id):
        if not self.getClient(client_id):
            return False

        if client_id.startswith('D-'):
            # This is a dynamically registered client
            self.del_unique_data('client', client_id[2:])
        else:
            # This is a statically configured client
            self.static_store.delete_options('client', client_id)

        if self.getClient(client_id):
            return False
        return True

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

        token['token_id'] = token_id

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

        new_token = '%s_%s' % (token['token_id'], token_security_check)
        refresh_token = 'R_%s_%s' % (token['token_id'], refresh_security_check)

        return {
            'access_token': new_token,
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

    def invalidateToken(self, token_id):
        data = self.get_unique_data('token', token_id)
        if data:
            datum = data[token_id]
            self.del_unique_data('userinfo', datum['userinfocode'])

        self.del_unique_data('token', token_id)

    def revokeConsent(self, username, client_id):
        data = self.get_unique_data('token', name='username', value=username)

        removed_token = False
        for uuid in data.keys():
            token = self.get_unique_data('token', uuid)[uuid]
            if token['client_id'] == client_id:
                self.invalidateToken(uuid)
                removed_token = True

        return removed_token

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

    def _cleanupExpiredTokens(self):
        tokens = self.get_unique_data('token')
        cleaned = 0
        for iden in tokens:
            if tokens[iden]['expires_at'] <= int(time.time()):
                cleaned += 1
                self.invalidateToken(iden)
        return cleaned

    def _cleanupUnreferencedTokens(self):
        tokens = self.get_unique_data('token')
        cleaned = 0
        for iden in tokens:
            if not self.getClient(tokens[iden]['client_id']):
                cleaned += 1
                self.invalidateToken(iden)
        return cleaned

    def _cleanup(self):
        res1 = self._cleanupExpiredTokens()
        res2 = self._cleanupUnreferencedTokens()
        return res1 + res2

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
