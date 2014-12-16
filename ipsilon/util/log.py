# Copyright (C) 2014 Ipsilon Project Contributors
#
# See the file named COPYING for the project license

import cherrypy
import inspect


class Log(object):

    def debug(self, fact):
        if cherrypy.config.get('debug', False):
            s = inspect.stack()
            cherrypy.log('DEBUG(%s): %s' % (s[1][3], fact))

    # for compatibility with existing code
    _debug = debug

    def log(self, fact):
        cherrypy.log(fact)

    def error(self, fact):
        cherrypy.log.error('ERROR: %s' % fact)
