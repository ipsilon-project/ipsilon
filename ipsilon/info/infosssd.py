# Copyright (C) 2014 Ipsilon project Contributors, for license see COPYING

# Info plugin for SSSD attributes via DBus

from ipsilon.info.common import InfoProviderBase
from ipsilon.info.common import InfoProviderInstaller
from ipsilon.util.plugin import PluginObject
from ipsilon.util.policy import Policy
from ipsilon.util import config as pconfig
import time
import subprocess
import SSSDConfig
import logging
import dbus

SSSD_CONF = '/etc/sssd/sssd.conf'

# LDAP attributes to tell SSSD to fetch over the InfoPipe
SSSD_ATTRS = ['mail',
              'street',
              'locality',
              'st',
              'postalCode',
              'telephoneNumber',
              'givenname',
              'sn']

# These are mapped from the infosssd configuration in sssd.conf
sssd_mapping = [
    ['gecos', 'fullname'],
    ['mail', 'email'],
    ['givenname', 'givenname'],
    ['sn', 'surname'],
    ['street', 'street'],
    ['st', 'state'],
    ['locality', 'city'],
    ['postalCode', 'postcode'],
    ['telephoneNumber', 'phone'],
    ['*', '*'],
]


class InfoProvider(InfoProviderBase):

    def __init__(self, *pargs):
        super(InfoProvider, self).__init__(*pargs)
        self.mapper = Policy(sssd_mapping)
        self.name = 'sssd'
        self.description = """
Info plugin that uses DBus to retrieve user data from SSSd."""
        self.bus = None
        self.new_config(
            self.name,
            pconfig.Condition(
                'preconfigured',
                'SSSD can only be used when pre-configured',
                False),
        )

    def _get_user_data(self, user):
        reply = dict()
        groups = []

        # Get object for sssd infopipe
        infosssd_obj = self.bus.get_object('org.freedesktop.sssd.infopipe',
                                           '/org/freedesktop/sssd/infopipe')

        # Get Users object and interface from DBus
        users_obj = self.bus.get_object('org.freedesktop.sssd.infopipe',
                                        '/org/freedesktop/sssd/infopipe/Users')
        users_if = dbus.Interface(users_obj,
                                  'org.freedesktop.sssd.infopipe.Users')

        # Get path, object, and interface for specific user
        user_path = users_if.FindByName(user)
        user_obj = self.bus.get_object('org.freedesktop.sssd.infopipe',
                                       user_path)

        # Get GECOS, attributes, and groups
        reply['gecos'] = str(user_obj.Get(
            'org.freedesktop.sssd.infopipe.Users.User',
            'gecos',
            dbus_interface=dbus.PROPERTIES_IFACE))
        user_attrs = user_obj.Get('org.freedesktop.sssd.infopipe.Users.User',
                                  'extraAttributes',
                                  dbus_interface=dbus.PROPERTIES_IFACE)
        user_groups = infosssd_obj.GetUserGroups(
            user,
            dbus_interface='org.freedesktop.sssd.infopipe')

        for group in user_groups:
            groups.append(str(group))

        for attr_name in user_attrs:
            attr_name = str(attr_name)
            if len(user_attrs[attr_name]) == 1:
                reply[attr_name] = str(user_attrs[attr_name][0])
            else:
                reply[attr_name] = []
                for attr_val in user_attrs[attr_name]:
                    reply[attr_name].append(str(attr_val))

        return reply, groups

    def get_user_attrs(self, user):
        reply = dict()
        try:
            attrs, groups = self._get_user_data(user)
            userattrs, extras = self.mapper.map_attributes(attrs)
            reply = userattrs
            reply['_groups'] = groups
            reply['_extras'] = {'sssd': extras}

        except KeyError:
            pass

        return reply

    def save_plugin_config(self, *args, **kwargs):
        raise ValueError('Configuration cannot be modified live for SSSD')

    def get_config_obj(self):
        return None

    def enable(self):
        self.refresh_plugin_config()
        if not self.get_config_value('preconfigured'):
            raise Exception("SSSD Can be enabled only if pre-configured")
        self.bus = dbus.SystemBus()
        super(InfoProvider, self).enable()


class Installer(InfoProviderInstaller):

    def __init__(self, *pargs):
        super(Installer, self).__init__()
        self.name = 'sssd'
        self.pargs = pargs

    def install_args(self, group):
        group.add_argument('--info-sssd', choices=['yes', 'no'],
                           default='no',
                           help='Use SSSD to populate user attributes'
                                ' via DBus')
        group.add_argument('--info-sssd-domain', action='append',
                           help='SSSD domain to enable for attribute'
                                ' passthrough')

    def configure(self, opts, changes):
        if opts['info_sssd'] != 'yes':
            return

        configured = 0

        try:
            sssdconfig = SSSDConfig.SSSDConfig()
            sssdconfig.import_config()
        except Exception as e:  # pylint: disable=broad-except
            # Unable to read existing SSSD config so it is probably not
            # configured.
            logging.info('Loading SSSD config failed: %s', e)
            return False

        if not opts['info_sssd_domain']:
            domains = sssdconfig.list_domains()
        else:
            domains = opts['info_sssd_domain']

        changes['domains'] = {}
        for domain in domains:
            changes['domains'][domain] = {}
            try:
                sssd_domain = sssdconfig.get_domain(domain)
            except SSSDConfig.NoDomainError:
                logging.info('No SSSD domain %s', domain)
                continue
            else:
                try:
                    changes['domains'][domain] = {
                        'ldap_user_extra_attrs':
                            # noqa (pep8 E126)
                            sssd_domain.get_option('ldap_user_extra_attrs')}
                except SSSDConfig.NoOptionError:
                    pass
                sssd_domain.set_option(
                    'ldap_user_extra_attrs', ', '.join(SSSD_ATTRS)
                )
                sssdconfig.save_domain(sssd_domain)
                configured += 1
                logging.info("Configured SSSD domain %s", domain)

        if configured == 0:
            logging.info('No SSSD domains configured')
            return False

        changes['ifp'] = {}
        try:
            sssdconfig.new_service('ifp')
            changes['ifp']['new'] = True
        except SSSDConfig.ServiceAlreadyExists:
            changes['ifp']['new'] = False

        sssdconfig.activate_service('ifp')

        ifp = sssdconfig.get_service('ifp')
        if not changes['ifp']['new']:
            try:
                changes['ifp']['allowed_uids'] = ifp.get_option('allowed_uids')
            except SSSDConfig.NoOptionError:
                pass
            try:
                changes['ifp']['user_attributes'] = ifp.get_option(
                    'user_attributes')
            except SSSDConfig.NoOptionError:
                pass
        ifp.set_option('allowed_uids', 'ipsilon, root')
        ifp.set_option('user_attributes', '+' + ', +'.join(SSSD_ATTRS))

        sssdconfig.save_service(ifp)
        sssdconfig.write(SSSD_CONF)

        # for selinux enabled platforms, ignore if it fails just report
        try:
            subprocess.call(['/usr/sbin/setsebool', '-P',
                             'httpd_dbus_sssd=on'])
        except Exception:  # pylint: disable=broad-except
            pass

        try:
            subprocess.call(['/sbin/service', 'sssd', 'restart'])
        except Exception:  # pylint: disable=broad-except
            pass

        # Give SSSD a chance to restart
        time.sleep(5)

        # Add configuration data to database
        po = PluginObject(*self.pargs)
        po.name = 'sssd'
        po.wipe_data()
        po.wipe_config_values()
        config = {'preconfigured': 'True'}
        po.save_plugin_config(config)

        # Update global config to add info plugin
        po.is_enabled = True
        po.save_enabled_state()

    def unconfigure(self, opts, changes):
        if 'domains' not in changes:
            # We always record domains on configure, if we don't have that, we
            # were not configured.
            return

        try:
            sssdconfig = SSSDConfig.SSSDConfig()
            sssdconfig.import_config()
        except Exception as e:  # pylint: disable=broad-except
            # Unable to read existing SSSD config so it is probably not
            # configured.
            logging.info('Loading SSSD config failed: %s', e)
            return False

        for domain in changes['domains']:
            try:
                sssd_domain = sssdconfig.get_domain(domain.encode('utf-8'))
            except SSSDConfig.NoDomainError:
                logging.info('No SSSD domain %s', domain)
                continue
            else:
                if 'ldap_user_extra_attrs' in changes['domains'][domain]:
                    sssd_domain.set_option('ldap_user_extra_attrs',
                                           changes['domains'][domain][
                                               'ldap_user_extra_attrs'].encode(
                                               'utf-8'))
                else:
                    sssd_domain.remove_option('ldap_user_extra_attrs')
                sssdconfig.save_domain(sssd_domain)

        if changes['ifp']['new']:
            # We created the service newly, let's remove
            sssdconfig.delete_service('ifp')
        else:
            ifp = sssdconfig.get_service('ifp')
            if 'allowed_uids' in changes['ifp']:
                ifp.set_option('allowed_uids',
                               changes['ifp']['allowed_uids'].encode('utf-8'))
            if 'user_attributes' in changes['ifp']:
                ifp.set_option('user_attributes',
                               changes['ifp']['user_attributes'].encode(
                                   'utf-8'))
            sssdconfig.save_service(ifp)

        sssdconfig.write(SSSD_CONF)

        try:
            subprocess.call(['/sbin/service', 'sssd', 'restart'])
        except Exception:  # pylint: disable=broad-except
            pass

        # Give SSSD a chance to restart
        time.sleep(5)
