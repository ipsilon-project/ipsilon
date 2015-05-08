# Copyright (C) 2014 Ipsilon project Contributors, for license see COPYING

from ipsilon.info.common import InfoProviderBase
from ipsilon.info.common import InfoProviderInstaller
from ipsilon.util.plugin import PluginObject
from ipsilon.util.policy import Policy
import grp
import pwd
import os


posix_map = [
    ['gecos', 'fullname']
]


class InfoProvider(InfoProviderBase):

    def __init__(self, *pargs):
        super(InfoProvider, self).__init__(*pargs)
        self.mapper = Policy(posix_map)
        self.name = 'nss'
        self.new_config(self.name)

    def _get_posix_user(self, user):
        p = pwd.getpwnam(user)
        return {'username': p.pw_name, 'uidNumber': p.pw_uid,
                'gidNumber': p.pw_gid, 'gecos': p.pw_gecos,
                'homeDirectory': p.pw_dir, 'loginShell': p.pw_shell}

    def _get_posix_groups(self, user, group):
        groups = set()
        getgrouplist = getattr(os, 'getgrouplist', None)
        if getgrouplist:
            ids = getgrouplist(user, group)
            for i in ids:
                try:
                    g = grp.getgrgid(i)
                    groups.add(g.gr_name)
                except KeyError:
                    pass

        else:
            g = grp.getgrgid(group)
            groups.add(g.gr_name)

            allg = grp.getgrall()
            for g in allg:
                if user in g.gr_mem:
                    groups.add(g.gr_name)

        return list(groups)

    def get_user_attrs(self, user):
        reply = dict()
        try:
            posix_user = self._get_posix_user(user)
            userattrs, extras = self.mapper.map_attributes(posix_user)
            groups = self._get_posix_groups(posix_user['username'],
                                            posix_user['gidNumber'])
            reply = userattrs
            reply['_groups'] = groups
            reply['_extras'] = {'posix': extras}

        except KeyError:
            pass

        return reply


class Installer(InfoProviderInstaller):

    def __init__(self, *pargs):
        super(Installer, self).__init__()
        self.name = 'nss'
        self.pargs = pargs

    def install_args(self, group):
        group.add_argument('--info-nss', choices=['yes', 'no'], default='no',
                           help='Use passwd data to populate user attrs')

    def configure(self, opts, changes):
        if opts['info_nss'] != 'yes':
            return

        # Add configuration data to database
        po = PluginObject(*self.pargs)
        po.name = 'nss'
        po.wipe_data()
        po.wipe_config_values()

        # Update global config to add info plugin
        po.is_enabled = True
        po.save_enabled_state()
