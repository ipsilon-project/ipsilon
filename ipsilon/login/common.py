#!/usr/bin/python
#
# Copyright (C) 2013  Simo Sorce <simo@redhat.com>
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

from ipsilon.util.log import Log
from ipsilon.util.page import Page
from ipsilon.util.user import UserSession
from ipsilon.util.plugin import PluginLoader, PluginObject
from ipsilon.util.plugin import PluginInstaller
from ipsilon.info.common import Info
from ipsilon.util.cookies import SecureCookie
from ipsilon.util.trans import Transaction
import cherrypy


USERNAME_COOKIE = 'ipsilon_default_username'


class LoginManagerBase(PluginObject, Log):

    def __init__(self):
        super(LoginManagerBase, self).__init__()
        self.path = '/'
        self.next_login = None
        self.info = None

    def redirect_to_path(self, path):
        base = cherrypy.config.get('base.mount', "")
        raise cherrypy.HTTPRedirect('%s/login/%s' % (base, path))

    def auth_successful(self, trans, username, auth_type=None, userdata=None):
        session = UserSession()

        if self.info:
            userattrs = self.info.get_user_attrs(username)
            if userdata:
                userdata.update(userattrs or {})
            else:
                userdata = userattrs
            self.debug("User %s attributes: %s" % (username, repr(userdata)))

        if auth_type:
            if userdata:
                userdata.update({'auth_type': auth_type})
            else:
                userdata = {'auth_type': auth_type}

        # create session login including all the userdata just gathered
        session.login(username, userdata)

        # save username into a cookie if parent was form base auth
        if auth_type == 'password':
            cookie = SecureCookie(USERNAME_COOKIE, username)
            # 15 days
            cookie.maxage = 1296000
            cookie.send()

        transdata = trans.retrieve()
        self.debug(transdata)
        redirect = transdata.get('login_return',
                                 cherrypy.config.get('base.mount', "") + '/')
        self.debug('Redirecting back to: %s' % redirect)

        # on direct login the UI (ie not redirected by a provider) we ned to
        # remove the transaction cookie as it won't be needed anymore
        if trans.provider == 'login':
            trans.wipe()
        raise cherrypy.HTTPRedirect(redirect)

    def auth_failed(self, trans):
        # try with next module
        if self.next_login:
            return self.redirect_to_path(self.next_login.path)

        # return to the caller if any
        session = UserSession()

        transdata = trans.retrieve()

        # on direct login the UI (ie not redirected by a provider) we ned to
        # remove the transaction cookie as it won't be needed anymore
        if trans.provider == 'login':
            trans.wipe()

        # destroy session and return error
        if 'login_return' not in transdata:
            session.logout(None)
            raise cherrypy.HTTPError(401)

        raise cherrypy.HTTPRedirect(transdata['login_return'])

    def get_tree(self, site):
        raise NotImplementedError

    def enable(self, site):
        plugins = site[FACILITY]
        if self in plugins['enabled']:
            return

        # configure self
        if self.name in plugins['config']:
            self.set_config(plugins['config'][self.name])

        # and add self to the root
        root = plugins['root']
        root.add_subtree(self.name, self.get_tree(site))

        # finally add self in login chain
        prev_obj = None
        for prev_obj in plugins['enabled']:
            if prev_obj.next_login:
                break
        if prev_obj:
            while prev_obj.next_login:
                prev_obj = prev_obj.next_login
            prev_obj.next_login = self
        if not root.first_login:
            root.first_login = self

        plugins['enabled'].append(self)
        self._debug('Login plugin enabled: %s' % self.name)

        # Get handle of the info plugin
        self.info = root.info

    def disable(self, site):
        plugins = site[FACILITY]
        if self not in plugins['enabled']:
            return

        # remove self from chain
        root = plugins['root']
        if root.first_login == self:
            root.first_login = self.next_login
        elif root.first_login:
            prev_obj = root.first_login
            while prev_obj.next_login != self:
                prev_obj = prev_obj.next_login
            if prev_obj:
                prev_obj.next_login = self.next_login
        self.next_login = None

        plugins['enabled'].remove(self)
        self._debug('Login plugin disabled: %s' % self.name)


class LoginPageBase(Page):

    def __init__(self, site, mgr):
        super(LoginPageBase, self).__init__(site)
        self.lm = mgr
        self._Transaction = None

    def root(self, *args, **kwargs):
        raise cherrypy.HTTPError(500)


class LoginFormBase(LoginPageBase):

    def __init__(self, site, mgr, page, template=None):
        super(LoginFormBase, self).__init__(site, mgr)
        self.formpage = page
        self.formtemplate = template or 'login/form.html'
        self.trans = None

    def GET(self, *args, **kwargs):
        context = self.create_tmpl_context()
        # pylint: disable=star-args
        return self._template(self.formtemplate, **context)

    def root(self, *args, **kwargs):
        self.trans = Transaction('login', **kwargs)
        op = getattr(self, cherrypy.request.method, self.GET)
        if callable(op):
            return op(*args, **kwargs)

    def create_tmpl_context(self, **kwargs):
        next_url = None
        if self.lm.next_login is not None:
            next_url = '%s?%s' % (self.lm.next_login.path,
                                  self.trans.get_GET_arg())

        cookie = SecureCookie(USERNAME_COOKIE)
        cookie.receive()
        username = cookie.value
        if username is None:
            username = ''

        if self.trans is not None:
            tid = self.trans.transaction_id
        if tid is None:
            tid = ''

        context = {
            "title": 'Login',
            "action": '%s/%s' % (self.basepath, self.formpage),
            "service_name": self.lm.service_name,
            "username_text": self.lm.username_text,
            "password_text": self.lm.password_text,
            "description": self.lm.help_text,
            "next_url": next_url,
            "username": username,
        }
        context.update(kwargs)
        if self.trans is not None:
            t = self.trans.get_POST_tuple()
            context.update({t[0]: t[1]})

        return context


FACILITY = 'login_config'


class Login(Page):

    def __init__(self, *args, **kwargs):
        super(Login, self).__init__(*args, **kwargs)
        self.first_login = None
        self.info = Info(self._site)

        loader = PluginLoader(Login, FACILITY, 'LoginManager')
        self._site[FACILITY] = loader.get_plugin_data()
        plugins = self._site[FACILITY]

        available = plugins['available'].keys()
        self._debug('Available login managers: %s' % str(available))

        plugins['root'] = self
        for item in plugins['whitelist']:
            self._debug('Login plugin in whitelist: %s' % item)
            if item not in plugins['available']:
                continue
            plugins['available'][item].enable(self._site)

    def add_subtree(self, name, page):
        self.__dict__[name] = page

    def root(self, *args, **kwargs):
        if self.first_login:
            trans = Transaction('login', **kwargs)
            redirect = '%s/login/%s?%s' % (self.basepath,
                                           self.first_login.path,
                                           trans.get_GET_arg())
            raise cherrypy.HTTPRedirect(redirect)
        return self._template('login/index.html', title='Login')


class Logout(Page):

    def root(self, *args, **kwargs):
        UserSession().logout(self.user)
        return self._template('logout.html', title='Logout')


class LoginMgrsInstall(object):

    def __init__(self):
        pi = PluginInstaller(LoginMgrsInstall)
        self.plugins = pi.get_plugins()
