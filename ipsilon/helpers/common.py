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

from ipsilon.util.plugin import PluginInstaller


FACILITY = 'environment_helpers'


class EnvHelpersInstaller(object):
    def __init__(self):
        self.facility = FACILITY
        self.ptype = 'helper'
        self.name = None

    def unconfigure(self, opts):
        return

    def install_args(self, group):
        raise NotImplementedError

    def configure_server(self, opts):
        raise NotImplementedError


class EnvHelpersInstall(object):

    def __init__(self):
        pi = PluginInstaller(EnvHelpersInstall, FACILITY)
        self.plugins = pi.get_plugins()
