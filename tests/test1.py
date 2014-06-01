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


from lxml import html
import os
import pwd
import requests
import sys
import urlparse


def get_session(srvs, url):
    for srv in srvs:
        if url.startswith(srv['baseuri']):
            return srv['session']

    raise ValueError("Unknown URL: %s" % url)


def get_url(srvs, url, **kwargs):
    session = get_session(srvs, url)
    return session.get(url, allow_redirects=False, **kwargs)


def post_url(srvs, url, **kwargs):
    session = get_session(srvs, url)
    return session.post(url, allow_redirects=False, **kwargs)


def access_url(action, srvs, url, **kwargs):
    if action == 'get':
        return get_url(srvs, url, **kwargs)
    elif action == 'post':
        return post_url(srvs, url, **kwargs)
    else:
        raise ValueError("Unknown action type: [%s]" % action)


def get_new_url(referer, action):
    if action.startswith('/'):
        u = urlparse.urlparse(referer)
        return '%s://%s%s' % (u.scheme, u.netloc, action)
    return action


def parse_first(tree, rule):
    result = tree.xpath(rule)
    if type(result) is list:
        if len(result) > 0:
            result = result[0]
        else:
            result = None
    return result


def parse_list(tree, rule):
    result = tree.xpath(rule)
    if type(result) is list:
        return result
    return [result]


def handle_login_form(idp, r):
    tree = html.fromstring(r.text)
    try:
        action_url = parse_first(tree, '//form[@id="login_form"]/@action')
        method = parse_first(tree, '//form[@id="login_form"]/@method')
    except Exception:  # pylint: disable=broad-except
        return []

    if action_url is None:
        return []

    headers = {'referer': r.url}
    payload = {'login_name': idp['user'],
               'login_password': idp['pass']}

    return [method,
            get_new_url(r.url, action_url),
            {'headers': headers, 'data': payload}]


def handle_return_form(r):
    tree = html.fromstring(r.text)
    try:
        action_url = parse_first(tree, '//form[@id="saml-response"]/@action')
        method = parse_first(tree, '//form[@id="saml-response"]/@method')
        names = parse_list(tree, '//form[@id="saml-response"]/input/@name')
        values = parse_list(tree, '//form[@id="saml-response"]/input/@value')
    except Exception:  # pylint: disable=broad-except
        return []

    if action_url is None:
        return []

    headers = {'referer': r.url}
    payload = {}
    for i in range(0, len(names)):
        payload[names[i]] = values[i]

    return [method,
            get_new_url(r.url, action_url),
            {'headers': headers, 'data': payload}]


def go_to_url(srvs, idp, start_url, target_url):

    url = start_url
    action = 'get'
    args = {}

    good = True
    while good:
        r = access_url(action, srvs, url, **args)  # pylint: disable=star-args
        if r.status_code == 303:
            url = r.headers['location']
            action = 'get'
            args = {}
        elif r.status_code == 200:
            if url == target_url:
                return r.text

            result = handle_login_form(idp, r)
            if result:
                action = result[0]
                url = result[1]
                args = result[2]
                continue

            result = handle_return_form(r)
            if result:
                action = result[0]
                url = result[1]
                args = result[2]
                continue

            raise ValueError("Unhandled Success code at url %s" % url)

        else:
            good = False

    raise ValueError("Unhandled status (%d) on url %s" % (r.status_code, url))


def auth_to_idp(idp):

    target_url = '%s/%s/' % (idp['baseuri'], idp['name'])
    srvs = [idp]

    r = access_url('get', srvs, target_url)
    if r.status_code != 200:
        print >> sys.stderr, " ERROR: Access to idp failed: %s" % repr(r)
        return False

    tree = html.fromstring(r.text)
    try:
        expected = 'Log In'
        login = parse_first(tree, '//div[@id="content"]/p/a/text()')
        if login != expected:
            print >> sys.stderr, " ERROR: Expected [%s] got [%s]" % (expected,
                                                                     login)
        href = parse_first(tree, '//div[@id="content"]/p/a/@href')
        start_url = get_new_url(target_url, href)
    except Exception, e:  # pylint: disable=broad-except
        print >> sys.stderr, " ERROR: Unexpected reply [%s]" % repr(e)
        return False

    try:
        page = go_to_url(srvs, idp, start_url, target_url)
    except Exception, e:  # pylint: disable=broad-except
        print >> sys.stderr, " ERROR: %s" % repr(e)
        return False

    tree = html.fromstring(page)
    try:
        welcome = parse_first(tree, '//div[@id="welcome"]/p/text()')
    except Exception, e:  # pylint: disable=broad-except
        print >> sys.stderr, " ERROR: Unexpected reply [%s]" % repr(e)
        return False

    expected = 'Welcome %s!' % idp['user']
    if welcome != expected:
        print >> sys.stderr, " ERROR: Expected [%s] got [%s]" % (expected,
                                                                 welcome)
        return False

    return True


def add_sp_metadata(idp, sp):
    url = '%s/%s/admin/providers/saml2/admin/new' % (idp['baseuri'],
                                                     idp['name'])
    headers = {'referer': url}
    payload = {'name': sp['name']}
    m = requests.get('%s/saml2/metadata' % sp['baseuri'])
    metafile = {'metafile': m.content}
    r = idp['session'].post(url, headers=headers,
                            data=payload, files=metafile)
    if r.status_code != 200:
        print >> sys.stderr, " ERROR: %s" % repr(r)
        return False

    tree = html.fromstring(r.text)
    try:
        alert = parse_first(tree,
                            '//div[@class="alert alert-success"]/p/text()')
    except Exception, e:  # pylint: disable=broad-except
        print >> sys.stderr, " ERROR: Unexpected reply [%s]" % repr(e)
        return False

    expected = 'SP Successfully added'
    if alert != expected:
        print >> sys.stderr, " ERROR: Expected [%s] got [%s]" % (expected,
                                                                 alert)
        return False

    return True


if __name__ == '__main__':
    basedir = sys.argv[1]

    idpsrv = {'name': 'idp1',
              'baseuri': 'http://127.0.0.10:45080',
              'session': requests.Session(),
              'user': pwd.getpwuid(os.getuid())[0],
              'pass': 'ipsilon'}
    spsrv = {'name': 'sp1',
             'baseuri': 'http://127.0.0.11:45081',
             'session': requests.Session()}

    print "test1: Authenticate to IDP ...",
    if not auth_to_idp(idpsrv):
        sys.exit(1)
    print " SUCCESS"

    print "test1: Add SP Metadata to IDP ...",
    if not add_sp_metadata(idpsrv, spsrv):
        sys.exit(1)
    print " SUCCESS"

    print "test1: Access SP Protected Area ...",
    servers = [idpsrv, spsrv]
    spurl = '%s/sp/' % (spsrv['baseuri'])
    try:
        text = go_to_url(servers, idpsrv, spurl, spurl)
    except ValueError, e:
        print >> sys.stderr, " ERROR: %s" % repr(e)
        sys.exit(1)
    if text != "WORKS!":
        print >> sys.stderr, "ERROR: Expected [WORKS!], got [%s]" % text
        sys.exit(1)
    print " SUCCESS"
