# Copyright (C) 2013 Ipsilon project Contributors, for license see COPYING

from ipsilon.util.page import Page
from ipsilon.util.user import UserSession
from ipsilon.util.plugin import PluginInstaller, PluginLoader
from ipsilon.util.plugin import PluginObject
from ipsilon.util.config import ConfigHelper
from ipsilon.info.common import Info
from ipsilon.util.cookies import SecureCookie
import cherrypy


USERNAME_COOKIE = 'ipsilon_default_username'


class LoginManagerBase(ConfigHelper, PluginObject):

    def __init__(self, *args):
        ConfigHelper.__init__(self)
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

    def other_login_stacks(self):
        plugins = self._site[FACILITY]
        stack = list()
        try:
            idx = plugins.enabled.index(self.name)
        except (ValueError, IndexError):
            idx = None
        for i in range(0, len(plugins.enabled)):
            if i == idx:
                continue
            stack.append(plugins.available[plugins.enabled[i]])
        return stack

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
        return self._template(self.formtemplate, **context)

    def root(self, *args, **kwargs):
        self.trans = self.get_valid_transaction('login', **kwargs)
        op = getattr(self, cherrypy.request.method, self.GET)
        if callable(op):
            return op(*args, **kwargs)

    def create_tmpl_context(self, **kwargs):
        other_stacks = None
        other_login_stacks = self.lm.other_login_stacks()
        if other_login_stacks:
            other_stacks = list()
            for ls in other_login_stacks:
                url = '%s?%s' % (ls.path, self.trans.get_GET_arg())
                name = ls.name
                other_stacks.append({'url': url, 'name': name})

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
            "other_stacks": other_stacks,
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
        self.debug('Available login managers: %s' % str(available))

        for item in plugins.available:
            plugin = plugins.available[item]
            plugin.register(self, self._site)

        for item in plugins.enabled:
            self.debug('Login plugin in enabled list: %s' % item)
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
    def __init__(self, *args, **kwargs):
        super(Logout, self).__init__(*args, **kwargs)
        self.handlers = {}

    def root(self, *args, **kwargs):
        us = UserSession()

        for provider in self.handlers:
            self.debug("Calling logout for provider %s" % provider)
            obj = self.handlers[provider]
            obj()

        us.logout(self.user)
        return self._template('logout.html', title='Logout')

    def add_handler(self, provider, handler):
        """
        Providers can register a logout handler here that is called
        when the IdP logout link is accessed.
        """
        self.handlers[provider] = handler


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

    def unconfigure(self, opts, changes):
        return

    def install_args(self, group):
        raise NotImplementedError

    def validate_args(self, args):
        return

    def configure(self, opts, changes):
        raise NotImplementedError


class LoginMgrsInstall(object):

    def __init__(self):
        pi = PluginInstaller(LoginMgrsInstall, FACILITY)
        self.plugins = pi.get_plugins()
