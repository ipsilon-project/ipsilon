# Copyright (C) 2015 Ipsilon project Contributors, for license see COPYING

import sys
import os


def find_config():
    cfgfile = None
    if (len(sys.argv) > 1):
        cfgfile = sys.argv[-1]
    elif os.path.isfile('ipsilon.conf'):
        cfgfile = 'ipsilon.conf'
    elif os.path.isfile('/etc/ipsilon/ipsilon.conf'):
        cfgfile = '/etc/ipsilon/ipsilon.conf'
    else:
        raise IOError("Configuration file not found")
    return cfgfile
