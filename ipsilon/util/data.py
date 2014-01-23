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
import sqlite3
import cherrypy

class Store(object):

    def __init__(self, path=None):
        if path is None:
            self._path = os.getcwd()
        else:
            self._path = path

    def _load_config(self, dbname):
        con = None
        rows = []
        try:
            con = sqlite3.connect(dbname)
            cur = con.cursor()
            cur.executescript("""
                CREATE TABLE IF NOT EXISTS config(name TEXT, value TEXT)
                """)
            cur.execute("SELECT * FROM config")
            rows = cur.fetchall()
            con.commit()
        except sqlite3.Error, e:
            if con:
                con.rollback()
            cherrypy.log.error("Failed to load config: [%s]" % e)
        finally:
            if con:
                con.close()

        conf = {}
        for row in rows:
            if row[0] in conf:
                # multivalued
                if conf[row[0]] is list:
                    conf[row[0]].append(row[1])
                else:
                    v = conf[row[0]]
                    conf[row[0]] = [v, row[1]]
            else:
                conf[row[0]] = row[1]

        return conf

    def get_admin_config(self):
        path = None
        if 'admin.config.db' in cherrypy.config:
            path = cherrypy.config['admin.config.db']
        if not path:
            path = os.path.join(self._path, 'adminconfig.sqlite')

        return self._load_config(path)

    def _load_user_prefs(self, dbname, user):
        con = None
        rows = []
        try:
            con = sqlite3.connect(dbname)
            cur = con.cursor()
            cur.executescript("""
                CREATE TABLE IF NOT EXISTS users(name TEXT,
                                                 option TEXT,
                                                 value TEXT)
                """)
            cur.execute("SELECT option, value FROM users "
                        "where name = '%s'" % user)
            rows = cur.fetchall()
            con.commit()
        except sqlite3.Error, e:
            if con:
                con.rollback()
            cherrypy.log.error("Failed to load %s's prefs from "
                               "%s: [%s]" % ( user, dbname, e))
        finally:
            if con:
                con.close()

        conf = {}
        for row in rows:
            conf[row[0]] = row[1]

        return conf

    def get_user_preferences(self, user):
        path = None
        if 'user.prefs.db' in cherrypy.config:
            path = cherrypy.config['user.prefs.db']
        if not path:
            path = os.path.join(self._path, 'userprefs.sqlite')

        return self._load_user_prefs(path, user)
