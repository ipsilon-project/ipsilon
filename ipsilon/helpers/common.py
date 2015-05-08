# Copyright (C) 2014 Ipsilon project Contributors, for license see COPYING

from ipsilon.util.plugin import PluginInstaller


FACILITY = 'environment_helpers'


class EnvHelpersInstaller(object):
    def __init__(self):
        self.facility = FACILITY
        self.ptype = 'helper'
        self.name = None

    def unconfigure(self, opts, changes):
        return

    def install_args(self, group):
        raise NotImplementedError

    def validate_args(self, args):
        return

    def configure_server(self, opts, changes):
        raise NotImplementedError


class EnvHelpersInstall(object):

    def __init__(self):
        pi = PluginInstaller(EnvHelpersInstall, FACILITY)
        self.plugins = pi.get_plugins()
