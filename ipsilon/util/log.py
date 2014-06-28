#!/usr/bin/python
#
# Copyright (C) 2014 Ipsilon Project Contributors
#
# See the file named COPYING for the project license

import cherrypy


class Log(object):

    def debug(self, fact):
        if cherrypy.config.get('debug', False):
            cherrypy.log(fact)

    # for compatibility with existing code
    _debug = debug

    def log(self, fact):
        cherrypy.log(fact)
