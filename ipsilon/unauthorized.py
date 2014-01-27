#!/usr/bin/python
#
# Copyright (C) 2014  Petr Vobornik <pvoborni@redhat.com>
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


class Unauthorized(Page):

    def root(self):
        cherrypy.response.status = "401 Unauthorized"
        return self._template('unauthorized.html', title='Unauthorized')
