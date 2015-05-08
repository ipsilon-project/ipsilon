# Copyright (C) 2014 Ipsilon project Contributors, for license see COPYING

from ipsilon.login.common import LoginFormBase, LoginManagerBase, \
    LoginManagerInstaller
from ipsilon.util.plugin import PluginObject
from ipsilon.util.user import UserSession
from ipsilon.util import config as pconfig
from string import Template
import cherrypy
import subprocess


class Form(LoginFormBase):

    def POST(self, *args, **kwargs):
        us = UserSession()
        us.remote_login()
        user = us.get_user()
        if not user.is_anonymous:
            return self.lm.auth_successful(self.trans, user.name, 'password')
        else:
            try:
                error = cherrypy.request.headers['EXTERNAL_AUTH_ERROR']
            except KeyError:
                error = "Unknown error using external authentication"
                cherrypy.log.error("Error: %s" % error)
            return self.lm.auth_failed(self.trans)


class LoginManager(LoginManagerBase):

    def __init__(self, *args, **kwargs):
        super(LoginManager, self).__init__(*args, **kwargs)
        self.name = 'form'
        self.path = 'form'
        self.page = None
        self.service_name = 'form'
        self.description = """
Form based login Manager. Relies on mod_intercept_form_submit plugin for
 actual authentication. """
        self.new_config(
            self.name,
            pconfig.String(
                'username text',
                'Text used to ask for the username at login time.',
                'Username'),
            pconfig.String(
                'password text',
                'Text used to ask for the password at login time.',
                'Password'),
            pconfig.String(
                'help text',
                'Text used to guide the user at login time.',
                'Insert your Username and Password and then submit.')
        )

    @property
    def help_text(self):
        return self.get_config_value('help text')

    @property
    def username_text(self):
        return self.get_config_value('username text')

    @property
    def password_text(self):
        return self.get_config_value('password text')

    def get_tree(self, site):
        self.page = Form(site, self, 'login/form')
        return self.page


CONF_TEMPLATE = """
LoadModule intercept_form_submit_module modules/mod_intercept_form_submit.so
LoadModule authnz_pam_module modules/mod_authnz_pam.so

<Location /${instance}/login/form>
  InterceptFormPAMService ${service}
  InterceptFormLogin login_name
  InterceptFormPassword login_password
  # InterceptFormLoginSkip admin
  # InterceptFormClearRemoteUserForSkipped on
  InterceptFormPasswordRedact on
</Location>
"""


class Installer(LoginManagerInstaller):

    def __init__(self, *pargs):
        super(Installer, self).__init__()
        self.name = 'form'
        self.pargs = pargs

    def install_args(self, group):
        group.add_argument('--form', choices=['yes', 'no'], default='no',
                           help='Configure External Form authentication')
        group.add_argument('--form-service', action='store', default='remote',
                           help='PAM service name to use for authentication')

    def configure(self, opts, changes):
        if opts['form'] != 'yes':
            return

        confopts = {'instance': opts['instance'],
                    'service': opts['form_service']}

        tmpl = Template(CONF_TEMPLATE)
        hunk = tmpl.substitute(**confopts)
        with open(opts['httpd_conf'], 'a') as httpd_conf:
            httpd_conf.write(hunk)

        # Add configuration data to database
        po = PluginObject(*self.pargs)
        po.name = 'form'
        po.wipe_data()
        po.wipe_config_values()

        # Update global config to add login plugin
        po.is_enabled = True
        po.save_enabled_state()

        # for selinux enabled platforms, ignore if it fails just report
        try:
            subprocess.call(['/usr/sbin/setsebool', '-P',
                             'httpd_mod_auth_pam=on'])
        except Exception:  # pylint: disable=broad-except
            pass
