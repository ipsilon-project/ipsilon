# Copyright (C) 2015 Ipsilon project Contributors, for license see COPYING

import os


def find_config(instance, path):
    cfgfile = None

    if path is not None:
        cfgfile = path
    elif instance is None:
        cfgfile = 'ipsilon.conf'
    elif instance != '':
        cfgfile = '/etc/ipsilon/%s/ipsilon.conf' % instance
    else:
        cfgfile = '/etc/ipsilon/ipsilon.conf'

    if not os.path.isfile(cfgfile):
        raise IOError("Configuration file not found")
    return cfgfile
