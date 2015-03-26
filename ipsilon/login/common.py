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

from ipsilon.util.page import Page
from ipsilon.util.user import UserSession
from ipsilon.util.plugin import PluginInstaller, PluginLoader
from ipsilon.util.plugin import PluginObject, PluginConfig
from ipsilon.info.common import Info
from ipsilon.util.cookies import SecureCookie
import cherrypy


USERNAME_COOKIE = 'ipsilon_default_username'


class LoginManagerBase(PluginConfig, PluginObject):

    def __init__(self, *args):
        PluginConfig.__init__(self)
        PluginObject.__init__(self, *args)
        self._root = None
        self._site = None
        self.path = '/'
        self.info = None

    def redirect_to_path(self, path, trans=None):
        base = cherrypy.config.get('base.mount', "")
        url = '%s/login/%s' % (base, path)
        if trans:
            url += '?%s' % trans.get_GET_arg()
        raise cherrypy.HTTPRedirect(url)

    def auth_successful(self, trans, username, auth_type=None, userdata=None):
        session = UserSession()

        # merge attributes from login plugin and info plugin
        if self.info:
            infoattrs = self.info.get_user_attrs(username)
        else:
            infoattrs = dict()

        if userdata is None:
            userdata = dict()

        if '_groups' in infoattrs:
            userdata['_groups'] = list(set(userdata.get('_groups', []) +
                                           infoattrs['_groups']))
            del infoattrs['_groups']

        if '_extras' in infoattrs:
            userdata['_extras'] = userdata.get('_extras', {})
            userdata['_extras'].update(infoattrs['_extras'])
            del infoattrs['_extras']

        userdata.update(infoattrs)

        self.debug("User %s attributes: %s" % (username, repr(userdata)))

        if auth_type:
            if userdata:
                userdata.update({'_auth_type': auth_type})
            else:
                userdata = {'_auth_type': auth_type}

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
            self.debug('Wiping transaction data')
            trans.wipe()
        raise cherrypy.HTTPRedirect(redirect)

    def auth_failed(self, trans):
        # try with next module
        next_login = self.next_login()
        if next_login:
            return self.redirect_to_path(next_login.path, trans)

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

    def set_auth_error(self):
        cherrypy.response.status = 401

    def get_tree(self, site):
        raise NotImplementedError

    def register(self, root, site):
        self._root = root
        self._site = site

    def next_login(self):
        plugins = self._site[FACILITY]
        try:
            idx = plugins.enabled.index(self.name)
            item = plugins.enabled[idx + 1]
            return plugins.available[item]
        except (ValueError, IndexError):
            return None

    def on_enable(self):

        # and add self to the root
        self._root.add_subtree(self.name, self.get_tree(self._site))

        # Get handle of the info plugin
        self.info = self._root.info


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
        self.trans = self.get_valid_transaction('login', **kwargs)
        op = getattr(self, cherrypy.request.method, self.GET)
        if callable(op):
            return op(*args, **kwargs)

    def create_tmpl_context(self, **kwargs):
        next_url = None
        next_login = self.lm.next_login()
        if next_login:
            next_url = '%s?%s' % (next_login.path,
                                  self.trans.get_GET_arg())

        cookie = SecureCookie(USERNAME_COOKIE)
        cookie.receive()
        username = cookie.value

        target = None
        if self.trans is not None:
            tid = self.trans.transaction_id
            target = self.trans.retrieve().get('login_target')
            username = self.trans.retrieve().get('login_username')
        if tid is None:
            tid = ''

        if username is None:
            username = ''

        context = {
            "title": 'Login',
            "action": '%s/%s' % (self.basepath, self.formpage),
            "service_name": self.lm.service_name,
            "username_text": self.lm.username_text,
            "password_text": self.lm.password_text,
            "description": self.lm.help_text,
            "next_url": next_url,
            "username": username,
            "login_target": target,
            "cancel_url": '%s/login/cancel?%s' % (self.basepath,
                                                  self.trans.get_GET_arg()),
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
        self.cancel = Cancel(*args, **kwargs)
        self.info = Info(self._site)

        plugins = PluginLoader(Login, FACILITY, 'LoginManager')
        plugins.get_plugin_data()
        self._site[FACILITY] = plugins

        available = plugins.available.keys()
        self._debug('Available login managers: %s' % str(available))

        for item in plugins.available:
            plugin = plugins.available[item]
            plugin.register(self, self._site)

        for item in plugins.enabled:
            self._debug('Login plugin in enabled list: %s' % item)
            if item not in plugins.available:
                continue
            plugins.available[item].enable()

    def add_subtree(self, name, page):
        self.__dict__[name] = page

    def get_first_login(self):
        plugin = None
        plugins = self._site[FACILITY]
        if plugins.enabled:
            first = plugins.enabled[0]
            plugin = plugins.available[first]
        return plugin

    def root(self, *args, **kwargs):
        plugin = self.get_first_login()
        if plugin:
            trans = self.get_valid_transaction('login', **kwargs)
            redirect = '%s/login/%s?%s' % (self.basepath,
                                           plugin.path,
                                           trans.get_GET_arg())
            raise cherrypy.HTTPRedirect(redirect)
        return self._template('login/index.html', title='Login')


class Logout(Page):

    def root(self, *args, **kwargs):
        UserSession().logout(self.user)
        return self._template('logout.html', title='Logout')


class Cancel(Page):

    def GET(self, *args, **kwargs):

        session = UserSession()
        session.logout(None)

        # return to the caller if any
        transdata = self.get_valid_transaction('login', **kwargs).retrieve()
        if 'login_return' not in transdata:
            raise cherrypy.HTTPError(401)
        raise cherrypy.HTTPRedirect(transdata['login_return'])

    def root(self, *args, **kwargs):
        op = getattr(self, cherrypy.request.method, self.GET)
        if callable(op):
            return op(*args, **kwargs)


class LoginManagerInstaller(object):
    def __init__(self):
        self.facility = FACILITY
        self.ptype = 'login'
        self.name = None

    def unconfigure(self, opts):
        return

    def install_args(self, group):
        raise NotImplementedError

    def validate_args(self, args):
        return

    def configure(self, opts):
        raise NotImplementedError


class LoginMgrsInstall(object):

    def __init__(self):
        pi = PluginInstaller(LoginMgrsInstall, FACILITY)
        self.plugins = pi.get_plugins()
