#!/usr/bin/python
#
# Copyright (C) 2014  Ipsilon Contributors see COPYING for license

from ipsilon.admin.common import AdminPlugins
from ipsilon.info.common import FACILITY


class InfoPlugins(AdminPlugins):
    def __init__(self, site, parent):
        super(InfoPlugins, self).__init__('info', site, parent, FACILITY)
        self.title = 'Info Plugins'
