#!/usr/bin/python
#
# Copyright (C) 2016 Ipsilon project Contributors, for license see COPYING

from helpers.common import IpsilonTestBase  # pylint: disable=relative-import
from helpers.http import HttpSessions  # pylint: disable=relative-import
import os
import json
import pwd
import sys
import requests
import hashlib
from string import Template

idp_g = {'TEMPLATES': '${TESTDIR}/templates/install',
         'CONFDIR': '${TESTDIR}/etc',
         'DATADIR': '${TESTDIR}/lib',
         'CACHEDIR': '${TESTDIR}/cache',
         'HTTPDCONFD': '${TESTDIR}/${NAME}/conf.d',
         'STATICDIR': '${ROOTDIR}',
         'BINDIR': '${ROOTDIR}/ipsilon',
         'WSGI_SOCKET_PREFIX': '${TESTDIR}/${NAME}/logs/wsgi'}


idp_a = {'hostname': '${ADDRESS}:${PORT}',
         'admin_user': '${TEST_USER}',
         'system_user': '${TEST_USER}',
         'instance': '${NAME}',
         'testauth': 'yes',
         'pam': 'no',
         'gssapi': 'no',
         'ipa': 'no',
         'openidc': 'yes',
         'openidc_subject_salt': 'testcase',
         'server_debugging': 'True'}


sp1_g = {'HTTPDCONFD': '${TESTDIR}/${NAME}/conf.d',
         'OPENIDC_TEMPLATE': '${TESTDIR}/templates/install/openidc/rp.conf',
         'CONFFILE': '${TESTDIR}/${NAME}/conf.d/ipsilon-%s.conf',
         'HTTPDIR': '${TESTDIR}/${NAME}/%s'}


sp1_a = {'hostname': '${ADDRESS}',
         'auth_location': '/sp',
         'openidc': 'yes',
         'openidc_idp_url': 'https://127.0.0.10:45080/idp1',
         'openidc_response_type': 'code',
         'openidc_skip_ssl_validation': 'yes',
         'httpd_user': '${TEST_USER}'}


sp2_g = {'HTTPDCONFD': '${TESTDIR}/${NAME}/conf.d',
         'OPENIDC_TEMPLATE': '${TESTDIR}/templates/install/openidc/rp.conf',
         'CONFFILE': '${TESTDIR}/${NAME}/conf.d/ipsilon-%s.conf',
         'HTTPDIR': '${TESTDIR}/${NAME}/%s'}


sp2_a = {'hostname': '${ADDRESS}',
         'auth_location': '/sp',
         'openidc': 'yes',
         'openidc_idp_url': 'https://127.0.0.10:45080/idp1',
         'openidc_response_type': 'id_token',
         'openidc_subject_type': 'public',
         'openidc_skip_ssl_validation': 'yes',
         'httpd_user': '${TEST_USER}'}


sp3_g = {'HTTPDCONFD': '${TESTDIR}/${NAME}/conf.d',
         'OPENIDC_TEMPLATE': '${TESTDIR}/templates/install/openidc/rp.conf',
         'CONFFILE': '${TESTDIR}/${NAME}/conf.d/ipsilon-%s.conf',
         'HTTPDIR': '${TESTDIR}/${NAME}/%s'}


sp3_a = {'hostname': '${ADDRESS}',
         'auth_location': '/sp',
         'openidc': 'yes',
         'openidc_idp_url': 'https://127.0.0.10:45080/idp1',
         'openidc_response_type': 'id_token token',
         'openidc_skip_ssl_validation': 'yes',
         'httpd_user': '${TEST_USER}'}


def fixup_sp_httpd(httpdir):
    location = """
AddOutputFilter INCLUDES .html

Alias /sp ${HTTPDIR}/sp

<Directory ${HTTPDIR}/sp>
    Options +Includes
    Require all granted
</Directory>
"""
    t = Template(location)
    text = t.substitute({'HTTPDIR': httpdir})
    with open(httpdir + '/conf.d/ipsilon-openidc.conf', 'a') as f:
        f.write(text)

    index = """<!--#printenv -->"""
    os.mkdir(httpdir + '/sp')
    with open(httpdir + '/sp/index.html', 'w') as f:
        f.write(index)


def convert_to_dict(envlist):
    values = {}
    for pair in envlist.split('\n'):
        if pair.find('=') > 0:
            (key, value) = pair.split('=', 1)
            if key.startswith('OIDC_') and not key.endswith('_0'):
                values[key] = value
    return values


def check_info_results(text, expected):
    """
    Logout, login, fetch RP page to get the info variables and
    compare the OIDC_CLAIM_ ones to what we expect.
    """

    # Confirm that the expected values are in the output and that there
    # are no unexpected OIDC_CLAIM_ vars, and drop the _0 version.
    data = convert_to_dict(text)

    toreturn = {}
    toreturn['access_token'] = data.pop('OIDC_access_token', None)
    toreturn['access_token_expires'] = data.pop('OIDC_access_token_expires',
                                                None)

    for key in expected:
        item = data.pop('OIDC_CLAIM_' + key)
        if item != expected[key]:
            raise ValueError('Expected %s, got %s' % (expected[key], item))

    # Ignore a couple of attributes
    ignored = ['exp', 'c_hash', 'at_hash', 'aud', 'nonce', 'iat', 'auth_time',
               'azp']
    for attr in ignored:
        data.pop('OIDC_CLAIM_%s' % attr, None)

    if len(data) > 0:
        raise ValueError('Unexpected values %s' % data)

    return toreturn


def check_text_results(text, expected):
    if expected not in text:
        raise ValueError("Expected text '%s' not found, got '%s'" %
                         (expected, text))


class IpsilonTest(IpsilonTestBase):

    def __init__(self):
        super(IpsilonTest, self).__init__('openidc', __file__)

    def setup_servers(self, env=None):
        print "Installing IDP server"
        name = 'idp1'
        addr = '127.0.0.10'
        port = '45080'
        idp = self.generate_profile(idp_g, idp_a, name, addr, port)
        conf = self.setup_idp_server(idp, name, addr, port, env)

        print "Starting IDP's httpd server"
        self.start_http_server(conf, env)

        print "Installing first SP server"
        name = 'sp1'
        addr = '127.0.0.11'
        port = '45081'
        sp = self.generate_profile(sp1_g, sp1_a, name, addr, port)
        conf = self.setup_sp_server(sp, name, addr, port, env)
        fixup_sp_httpd(os.path.dirname(conf))

        print "Starting first SP's httpd server"
        self.start_http_server(conf, env)

        print "Installing second SP server"
        name = 'sp2'
        addr = '127.0.0.12'
        port = '45082'
        sp = self.generate_profile(sp2_g, sp2_a, name, addr, port)
        conf = self.setup_sp_server(sp, name, addr, port, env)
        fixup_sp_httpd(os.path.dirname(conf))

        print "Starting second SP's httpd server"
        self.start_http_server(conf, env)

        print "Installing third SP server"
        name = 'sp3'
        addr = '127.0.0.13'
        port = '45083'
        sp = self.generate_profile(sp3_g, sp3_a, name, addr, port)
        conf = self.setup_sp_server(sp, name, addr, port, env)
        fixup_sp_httpd(os.path.dirname(conf))

        print "Starting third SP's httpd server"
        self.start_http_server(conf, env)


if __name__ == '__main__':

    idpname = 'idp1'
    sp1name = 'sp1'
    sp2name = 'sp2'
    sp3name = 'sp3'
    user = pwd.getpwuid(os.getuid())[0]

    sess = HttpSessions()
    sess.add_server(idpname, 'https://127.0.0.10:45080', user, 'ipsilon')
    sess.add_server(sp1name, 'https://127.0.0.11:45081')
    sess.add_server(sp2name, 'https://127.0.0.12:45082')
    sess.add_server(sp3name, 'https://127.0.0.13:45083')

    print "openidc: Authenticate to IDP ...",
    try:
        sess.auth_to_idp(idpname)
    except Exception as e:  # pylint: disable=broad-except
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "openidc: Registering test client ...",
    try:
        client_info = {
            'redirect_uris': ['https://invalid/'],
            'response_types': ['code'],
            'grant_types': ['authorization_code'],
            'application_type': 'web',
            'client_name': 'Test suite client',
            'client_uri': 'https://invalid/',
            'token_endpoint_auth_method': 'client_secret_post'
        }
        r = requests.post('https://127.0.0.10:45080/idp1/openidc/Registration',
                          json=client_info)
        r.raise_for_status()
        reg_resp = r.json()
    except Exception as e:  # pylint: disable=broad-except
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "openidc: Registering test client with none auth ...",
    try:
        client_info = {
            'redirect_uris': ['https://invalid/'],
            'response_types': ['code'],
            'grant_types': ['authorization_code'],
            'application_type': 'web',
            'client_name': 'Test suite client',
            'client_uri': 'https://invalid/',
            'token_endpoint_auth_method': 'none'
        }
        r = requests.post('https://127.0.0.10:45080/idp1/openidc/Registration',
                          json=client_info)
        r.raise_for_status()
        reg_resp_none = r.json()
    except Exception as e:  # pylint: disable=broad-except
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "openidc: Access first SP Protected Area ...",
    try:
        page = sess.fetch_page(idpname, 'https://127.0.0.11:45081/sp/',
                               require_consent=True)
        h = hashlib.sha256()
        h.update('127.0.0.11')
        h.update(user)
        h.update('testcase')
        expect = {
            'sub': h.hexdigest(),
            'iss': 'https://127.0.0.10:45080/idp1/openidc/',
            'amr': json.dumps([]),
            'acr': '0'
        }
        old_token = check_info_results(page.text, expect)
    except ValueError as e:
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "openidc: Log back in to first SP Protected Area without consent" \
        " ...",
    try:
        page = sess.fetch_page(idpname,
                               'https://127.0.0.11:45081/sp/redirect_uri?log'
                               'out=https%3A%2F%2F127.0.0.11%3A45081%2Fsp%2F',
                               require_consent=False)
    except ValueError as e:
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "openidc: Revoking SP consent ...",
    try:
        page = sess.revoke_all_consent(idpname)
    except ValueError as e:
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "openidc: Log back in to first SP Protected Area with consent ...",
    try:
        page = sess.fetch_page(idpname,
                               'https://127.0.0.11:45081/sp/redirect_uri?log'
                               'out=https%3A%2F%2F127.0.0.11%3A45081%2Fsp%2F',
                               require_consent=True)
        h = hashlib.sha256()
        h.update('127.0.0.11')
        h.update(user)
        h.update('testcase')
        expect = {
            'sub': h.hexdigest(),
            'iss': 'https://127.0.0.10:45080/idp1/openidc/',
            'amr': json.dumps([]),
            'acr': '0'
        }
        new_token = check_info_results(page.text, expect)
    except ValueError as e:
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "openidc: Update first SP client name ...",
    try:
        sess.update_options(
            idpname,
            'providers/openidc/admin/client/%s' % reg_resp['client_id'],
            {'Client Name': 'Test suite client updated'})
    except ValueError as e:
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "openidc: Retrieving token info ...",
    try:
        # Testing token without client auth
        r = requests.post('https://127.0.0.10:45080/idp1/openidc/TokenInfo',
                          data={'token': new_token['access_token']})
        if r.status_code != 401:
            raise Exception('No 401 provided')

        # Testing token where we removed part of token ID
        r = requests.post('https://127.0.0.10:45080/idp1/openidc/TokenInfo',
                          data={'token': new_token['access_token'][1:],
                                'client_id': reg_resp['client_id'],
                                'client_secret': reg_resp['client_secret']})
        r.raise_for_status()
        info = r.json()
        if info['active']:
            raise Exception('Token active')

        # Testing token where we rempoved part of check string
        r = requests.post('https://127.0.0.10:45080/idp1/openidc/TokenInfo',
                          data={'token': new_token['access_token'][:-1],
                                'client_id': reg_resp['client_id'],
                                'client_secret': reg_resp['client_secret']})
        r.raise_for_status()
        info = r.json()
        if info['active']:
            raise Exception('Token active')

        # Testing valid token
        r = requests.post('https://127.0.0.10:45080/idp1/openidc/TokenInfo',
                          data={'token': new_token['access_token'],
                                'client_id': reg_resp['client_id'],
                                'client_secret': reg_resp['client_secret']})
        r.raise_for_status()
        info = r.json()
        if 'error' in info:
            raise Exception('Token introspection returned error: %s'
                            % info['error'])
        if not info['active']:
            raise Exception('Token not active')
        if info['username'] != user:
            raise Exception('Token for different user?')
        if info['token_type'] != 'Bearer':
            raise Exception('Unexpected token type: %s' % info['token_type'])

        scopes_needed = ['openid']
        info['scope'] = info['scope'].split(' ')
        for scope in scopes_needed:
            if scope not in info['scope']:
                raise Exception('Missing scope: %s' % scope)
            info['scope'].remove(scope)
        if len(info['scope']) != 0:
            raise Exception('Unexpected scopes found: %s' % info['scope'])

        # Testing previously revoked token
        r = requests.post('https://127.0.0.10:45080/idp1/openidc/TokenInfo',
                          data={'token': old_token['access_token'],
                                'client_id': reg_resp['client_id'],
                                'client_secret': reg_resp['client_secret']})
        r.raise_for_status()
        info = r.json()
        if 'error' in info:
            raise Exception('Token introspection returned error: %s'
                            % info['error'])
        if info['active']:
            raise Exception('Revoked token active')
        if len(info) != 1:
            raise Exception('Token contained more info then inactive')

        # Delete test client and then try to use it
        sess.delete_oidc_client(idpname, reg_resp['client_id'])
        r = requests.post('https://127.0.0.10:45080/idp1/openidc/TokenInfo',
                          data={'token': new_token['access_token'],
                                'client_id': reg_resp['client_id'],
                                'client_secret': reg_resp['client_secret']})
        if r.status_code != 400:
            raise Exception('Deleted client accepted')
    except ValueError as e:
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "openidc: Using none-authenticated client ...",
    try:
        # Test that none-authed clients don't have access to token info
        r = requests.post(
            'https://127.0.0.10:45080/idp1/openidc/TokenInfo',
            data={'token': new_token['access_token'],
                  'client_id': reg_resp_none['client_id'],
                  'client_secret': reg_resp_none['client_secret']})
        if r.status_code != 400:
            raise Exception('None-authed client accepted')

        # Try the authorization flow
        page = sess.fetch_page(idpname,
                               'https://127.0.0.10:45080/idp1/openidc/'
                               'Authorization?scope=openid&response_type=code&'
                               'response_mode=query&redirect_uri='
                               'https://invalid/&client_id=' +
                               reg_resp_none['client_id'],
                               return_prefix='https://invalid/')
        target = page.result.headers['Location']
        code = target.replace('https://invalid/?code=', '')
        token_resp = requests.post(
            'https://127.0.0.10:45080/idp1/openidc/Token',
            data={'client_id': reg_resp_none['client_id'],
                  'grant_type': 'authorization_code',
                  'redirect_uri': 'https://invalid/',
                  'code': code})
        if token_resp.status_code != 200:
            raise Exception('Unable to get token from code')
        anon_token = token_resp.json()
        if not anon_token.get('token_type') == 'Bearer':
            raise Exception('Invalid token type returned')
        if 'access_token' not in anon_token:
            raise Exception('Did not get access token')

        # Test that none-authed clients also can't get their own token info
        r = requests.post(
            'https://127.0.0.10:45080/idp1/openidc/TokenInfo',
            data={'token': anon_token['access_token'],
                  'client_id': reg_resp_none['client_id'],
                  'client_secret': reg_resp_none['client_secret']})
        if r.status_code != 400:
            raise Exception('None-authed client accepted')

        # Test it does have tokeninfo access after setting to authed
        sess.update_options(
            idpname,
            'providers/openidc/admin/client/%s' % reg_resp_none['client_id'],
            {'Token Endpoint Auth Method': 'client_secret_post'})

        r = requests.post(
            'https://127.0.0.10:45080/idp1/openidc/TokenInfo',
            data={'token': anon_token['access_token'],
                  'client_id': reg_resp_none['client_id'],
                  'client_secret': reg_resp_none['client_secret']})
        if r.status_code != 200:
            raise Exception('Authed client not accepted')
    except ValueError as e:
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "openidc: Checking user info ...",
    try:
        # Testing user info without token
        r = requests.post('https://127.0.0.10:45080/idp1/openidc/UserInfo')
        if r.status_code != 403:
            raise Exception('No 403 provided with token-less request')

        # Testing valid token
        r = requests.post('https://127.0.0.10:45080/idp1/openidc/UserInfo',
                          data={'access_token': new_token['access_token']})
        r.raise_for_status()
        info = r.json()
        if 'sub' not in info:
            raise Exception('No sub claim provided')
        h = hashlib.sha256()
        h.update('127.0.0.11')
        h.update(user)
        h.update('testcase')
        if info['sub'] != h.hexdigest():
            raise Exception('Sub claim invalid')
    except ValueError as e:
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "openidc: Access second SP Protected Area ...",
    try:
        page = sess.fetch_page(idpname, 'https://127.0.0.12:45082/sp/')
        expect = {
            'sub': user,
            'iss': 'https://127.0.0.10:45080/idp1/openidc/',
            'amr': json.dumps([]),
            'acr': '0'
        }
        check_info_results(page.text, expect)
    except ValueError as e:
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "openidc: Access third SP Protected Area ...",
    try:
        page = sess.fetch_page(idpname, 'https://127.0.0.13:45083/sp/')
        h = hashlib.sha256()
        h.update('127.0.0.13')
        h.update(user)
        h.update('testcase')
        expect = {
            'sub': h.hexdigest(),
            'iss': 'https://127.0.0.10:45080/idp1/openidc/',
            'amr': json.dumps([]),
            'acr': '0'
        }
        check_info_results(page.text, expect)
    except ValueError as e:
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    print "openidc: Set IDP authz stack to deny",
    try:
        sess.disable_plugin(idpname, 'authz', 'allow')
        sess.enable_plugin(idpname, 'authz', 'deny')
    except Exception as e:  # pylint: disable=broad-except
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    sess2 = HttpSessions()
    sess2.add_server(idpname, 'https://127.0.0.10:45080', user, 'ipsilon')
    sess2.add_server(sp1name, 'https://127.0.0.11:45081')

    print "openidc: Access first SP Protected Area with IDP deny, with " \
        "pre-auth ...",
    try:
        sess2.auth_to_idp(idpname)
        page = sess2.fetch_page(idpname, 'https://127.0.0.11:45081/sp/')
        check_text_results(page.text,
                           'OpenID Connect Provider error: access_denied')
    except ValueError as e:
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"

    sess3 = HttpSessions()
    sess3.add_server(idpname, 'https://127.0.0.10:45080', user, 'ipsilon')
    sess3.add_server(sp1name, 'https://127.0.0.11:45081')

    print "openidc: Access first SP Protected Area with IDP deny, without " \
        "pre-auth ...",
    try:
        page = sess3.fetch_page(idpname, 'https://127.0.0.11:45081/sp/')
        check_text_results(page.text,
                           'OpenID Connect Provider error: access_denied')
    except ValueError as e:
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    print " SUCCESS"
