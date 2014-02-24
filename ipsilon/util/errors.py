#!/usr/bin/python
#
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

from ipsilon.util.page import Page
import cherrypy

class Errors(Page):

    def __init__(self, *args, **kwargs):
        super(Errors, self).__init__(*args, **kwargs)

    def _error_template(self, *args, **kwargs):
        # pylint: disable=star-args
        output_page = self._template(*args, **kwargs)
        # for some reason cherrypy will choke if the output
        # is a unicode object, so use str() here to please it
        return str(output_page)

    def handler(self, status, message, traceback, version):
        self._debug(repr([status, message, traceback, version]))
        return self._error_template('internalerror.html', title='Internal Error')

    def __call__(self, status, message, traceback, version):
        return self.handler(status, message, traceback, version)


class Error_400(Errors):

    def handler(self, status, message, traceback, version):
        return self._error_template('badrequest.html',
                                    title='Bad Request', message=message)

class Error_401(Errors):

    def handler(self, status, message, traceback, version):
        return self._error_template('unauthorized.html',
                                    title='Unauthorized', message=message)
