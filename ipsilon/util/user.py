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

from util import data

class Site(object):
    def __init__(self, value):
        # implement lookup of sites id for link/name
        self.link = value
        self.name = value

class User(object):
    def __init__(self, username):
        if username is None:
            self.name = None
            self._userdata = dict()
        else:
            self._userdata = self._get_user_data(username)
            self.name = username

    def _get_user_data(self, username):
        store = data.Store()
        return store._get_user_preferences(username)

    @property
    def is_admin(self):
        if 'is_admin' in self._userdata:
            if self._userdata['is_admin'] == '1':
                return True
        return False

    @is_admin.setter
    def is_admin(self, value):
        if value is True:
            self._userdata['is_admin'] = '1'
        else:
            self._userdata['is_admin'] = '0'

    @property
    def fullname(self):
        if 'fullname' in self._userdata:
            return self._userdata['fullname']
        else:
            return self.name

    @fullname.setter
    def fullname(self, value):
        self._userdata['fullname'] = value

    @property
    def sites(self):
        if 'sites' in self._userdata:
            d = []
            for site in self._userdata['sites']:
                d.append(Site(site))
        else:
            return []

    @sites.setter
    def sites(self):
        #TODO: implement setting sites via the user object ?
        raise AttributeError

