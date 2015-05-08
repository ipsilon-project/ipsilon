# Copyright (C) 2014 Ipsilon project Contributors, for license see COPYING

from ipsilon.admin.loginstack import LoginStackPlugins
from ipsilon.info.common import FACILITY


class InfoPlugins(LoginStackPlugins):
    def __init__(self, site, parent):
        super(InfoPlugins, self).__init__('info', site, parent, FACILITY)
        self.title = 'Info Plugins'
