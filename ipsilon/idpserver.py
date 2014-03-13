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

import sys
sys.stdout = sys.stderr

import os
import atexit
import cherrypy
from ipsilon.util.data import Store
from ipsilon.util import page
from ipsilon.root import Root
from jinja2 import Environment, FileSystemLoader

cfgfile = None
if (len(sys.argv) > 1):
    cfgfile = sys.argv[-1]
elif os.path.isfile('ipsilon.conf'):
    cfgfile = 'ipsilon.conf'
elif os.path.isfile('/etc/ipsilon/ipsilon.conf'):
    cfgfile = '/etc/ipsilon/ipsilon.conf'
else:
    raise IOError("Configuration file not found")

cherrypy.config.update(cfgfile)

datastore = Store()
admin_config = datastore.get_admin_config()
for option in admin_config:
    cherrypy.config[option] = admin_config[option]

cherrypy.tools.protect = cherrypy.Tool('before_handler', page.protect)

templates = os.path.join(cherrypy.config['base.dir'], 'templates')
template_env = Environment(loader=FileSystemLoader(templates))

if __name__ == "__main__":
    conf = {'/': {'tools.staticdir.root': os.getcwd()},
            '/ui': {'tools.staticdir.on': True,
                    'tools.staticdir.dir': 'ui'}}
    cherrypy.quickstart(Root('default', template_env), '/', conf)

else:
    cherrypy.config['environment'] = 'embedded'

    if cherrypy.__version__.startswith('3.0') and cherrypy.engine.state == 0:
        cherrypy.engine.start(blocking=False)
        atexit.register(cherrypy.engine.stop)

    application = cherrypy.Application(Root('default', template_env),
                                       script_name=None, config=None)
