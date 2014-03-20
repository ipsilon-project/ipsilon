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
        self._admin_dbname = self._get_admin_dbname()
        self._user_dbname = self._get_userprefs_dbname()

    def _get_admin_dbname(self):
        path = None
        if 'admin.config.db' in cherrypy.config:
            path = cherrypy.config['admin.config.db']
        if not path:
            path = os.path.join(self._path, 'adminconfig.sqlite')
        return path

    def _get_userprefs_dbname(self):
        path = None
        if 'user.prefs.db' in cherrypy.config:
            path = cherrypy.config['user.prefs.db']
        if not path:
            path = os.path.join(self._path, 'userprefs.sqlite')
        return path

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
        return self._load_config(self._admin_dbname)

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
                               "%s: [%s]" % (user, dbname, e))
        finally:
            if con:
                con.close()

        conf = {}
        for row in rows:
            conf[row[0]] = row[1]

        return conf

    def get_user_preferences(self, user):
        return self._load_user_prefs(self._user_dbname, user)

    def get_plugins_config(self, facility):
        con = None
        rows = []
        try:
            con = sqlite3.connect(self._admin_dbname)
            cur = con.cursor()
            cur.execute("CREATE TABLE IF NOT EXISTS " +
                        facility + " (name TEXT,option TEXT,value TEXT)")
            cur.execute("SELECT * FROM " + facility)
            rows = cur.fetchall()
            con.commit()
        except sqlite3.Error, e:
            if con:
                con.rollback()
            cherrypy.log.error("Failed to load %s config: [%s]" % (facility,
                                                                   e))
        finally:
            if con:
                con.close()

        lpo = []
        plco = dict()
        for row in rows:
            if row[0] == 'global':
                if row[1] == 'order':
                    lpo = row[2].split(',')
                continue
            if row[0] not in plco:
                # one dict per provider
                plco[row[0]] = dict()

            conf = plco[row[0]]
            if row[1] in conf:
                if conf[row[1]] is list:
                    conf[row[1]].append(row[2])
                else:
                    v = conf[row[1]]
                    conf[row[1]] = [v, row[2]]
            else:
                conf[row[1]] = row[2]

        return (lpo, plco)

    def get_plugin_config(self, facility, plugin):
        con = None
        rows = []
        try:
            con = sqlite3.connect(self._admin_dbname)
            cur = con.cursor()
            cur.execute("CREATE TABLE IF NOT EXISTS " +
                        facility + " (name TEXT,option TEXT,value TEXT)")
            cur.execute("SELECT option, value FROM " +
                        facility + " WHERE name=?", (plugin,))
            rows = cur.fetchall()
            con.commit()
        except sqlite3.Error, e:
            if con:
                con.rollback()
            fpe = (facility, plugin, e)
            cherrypy.log.error("Failed to get %s/%s config: [%s]" % fpe)
            raise
        finally:
            if con:
                con.close()

        res = dict()
        for (option, value) in rows:
            if option in res:
                if res[option] is list:
                    res[option].append(value)
                else:
                    v = res[option]
                    res[option] = [v, value]
            else:
                res[option] = value

        return res

    def save_plugin_config(self, facility, plugin, options):
        SELECT = "SELECT option, value FROM %s WHERE name=?" % facility
        UPDATE = "UPDATE %s SET value=? WHERE name=? AND option=?" % facility
        INSERT = "INSERT INTO %s VALUES(?,?,?)" % facility
        con = None
        try:
            con = sqlite3.connect(self._admin_dbname)
            cur = con.cursor()
            cur.execute("CREATE TABLE IF NOT EXISTS " +
                        facility + " (name TEXT,option TEXT,value TEXT)")
            curvals = dict()
            for row in cur.execute(SELECT, (plugin,)):
                curvals[row[0]] = row[1]

            for name in options:
                if name in curvals:
                    cur.execute(UPDATE, (options[name], plugin, name))
                else:
                    cur.execute(INSERT, (plugin, name, options[name]))

            con.commit()
        except sqlite3.Error, e:
            if con:
                con.rollback()
            cherrypy.log.error("Failed to store config: [%s]" % e)
            raise
        finally:
            if con:
                con.close()

    def wipe_plugin_config(self, facility, plugin):
        # Try to backup old data first, just in case ?
        try:
            con = sqlite3.connect(self._admin_dbname)
            cur = con.cursor()
            cur.execute("CREATE TABLE IF NOT EXISTS " +
                        facility + " (name TEXT,option TEXT,value TEXT)")
            cur.execute("DELETE FROM " + facility + " WHERE name=?",
                        (plugin,))
            con.commit()
        except sqlite3.Error, e:
            if con:
                con.rollback()
            cherrypy.log.error("Failed to wipe %s config: [%s]" % (plugin, e))
            raise
        finally:
            if con:
                con.close()

    def get_data(self, plugin, idval=None, name=None, value=None):
        con = None
        rows = []
        names = None
        values = ()
        if idval or name or value:
            names = ""
            if idval:
                names += " id=?"
                values = values + (idval,)
            if name:
                if len(names) != 0:
                    names += " AND"
                names += " name=?"
                values = values + (name,)
            if value:
                if len(names) != 0:
                    names += " AND"
                names += " value=?"
                values = values + (value,)
        try:
            con = sqlite3.connect(self._admin_dbname)
            cur = con.cursor()
            cur.execute("CREATE TABLE IF NOT EXISTS " +
                        plugin + "_data (id INTEGER, name TEXT, value TEXT)")
            if not names:
                cur.execute("SELECT * FROM " + plugin + "_data")
            else:
                cur.execute("SELECT * FROM " + plugin + "_data WHERE" +
                            names, values)
            rows = cur.fetchall()
            con.commit()
        except sqlite3.Error, e:
            if con:
                con.rollback()
            cherrypy.log.error("Failed to load %s data: [%s]" % (plugin, e))
            cherrypy.log.error(repr([names, values]))
        finally:
            if con:
                con.close()

        data = dict()
        for row in rows:
            if row[0] not in data:
                data[row[0]] = dict()

            item = data[row[0]]
            if row[1] in item:
                if item[row[1]] is list:
                    item[row[1]].append(row[2])
                else:
                    v = item[row[1]]
                    item[row[1]] = [v, row[2]]
            else:
                item[row[1]] = row[2]

        return data

    def save_data(self, plugin, data):
        SELECT = "SELECT name, value FROM %s_data WHERE id=?" % plugin
        UPDATE = "UPDATE %s_data SET value=? WHERE id=? AND name=?" % plugin
        INSERT = "INSERT INTO %s_data VALUES(?,?,?)" % plugin
        con = None
        try:
            con = sqlite3.connect(self._admin_dbname)
            cur = con.cursor()
            for idval in data:
                curvals = dict()
                for row in cur.execute(SELECT, (idval,)):
                    curvals[row[0]] = row[1]

                datum = data[idval]
                for name in datum:
                    if name in curvals:
                        cur.execute(UPDATE, (datum[name], idval, name))
                    else:
                        cur.execute(INSERT, (idval, name, datum[name]))

            con.commit()
        except sqlite3.Error, e:
            if con:
                con.rollback()
            cherrypy.log.error("Failed to store %s data: [%s]" % (plugin, e))
            raise
        finally:
            if con:
                con.close()

    def wipe_data(self, plugin):
        # Try to backup old data first, just in case
        try:
            con = sqlite3.connect(self._admin_dbname)
            cur = con.cursor()
            cur.execute("DROP TABLE IF EXISTS " + plugin + "_data")
            cur.execute("CREATE TABLE " + plugin + "_data"
                        "(id INTEGER, name TEXT, value TEXT)")
            con.commit()
        except sqlite3.Error, e:
            if con:
                con.rollback()
            cherrypy.log.error("Failed to wipe %s data: [%s]" % (plugin, e))
            raise
        finally:
            if con:
                con.close()
