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

import os
import imp
import cherrypy

class Plugins(object):

    def __init__(self, path=None):
        if path is None:
            self._path = os.getcwd()
        else:
            self._path = path
        self._providers_tree = None

    def _load_class(self, tree, class_type, file_name):
        cherrypy.log.error('Check module %s for class %s' % (file_name,
                                                             class_type))
        name, ext = os.path.splitext(os.path.split(file_name)[-1])
        try:
            if ext.lower() == '.py':
                mod = imp.load_source(name, file_name)
            elif ext.lower() == '.pyc':
                mod = imp.load_compiled(name, file_name)
            else:
                return
        except Exception, e:  # pylint: disable=broad-except
            cherrypy.log.error('Failed to load "%s" module: [%s]' % (name, e))
            return

        if hasattr(mod, class_type):
            tree[name] = getattr(mod, class_type)()
            cherrypy.log.error('Added module %s' % (name))

    def _load_classes(self, tree, path, class_type):
        files = None
        try:
            files = os.listdir(path)
        except Exception, e:  # pylint: disable=broad-except
            cherrypy.log.error('No modules in %s: [%s]' % (path, e))
            return

        for name in files:
            filename = os.path.join(path, name)
            self._load_class(tree, class_type, filename)

    def get_providers(self):
        if self._providers_tree is None:
            path = None
            if 'providers.dir' in cherrypy.config:
                path = cherrypy.config['providers.dir']
            if not path:
                path = os.path.join(self._path, 'providers')

            self._providers_tree = []
            self._load_classes(self._providers_tree, path, 'IdpProvider')

        return self._providers_tree

    def get_custom(self, path, class_type):
        tree = []
        self._load_classes(tree, path, class_type)
        return tree
