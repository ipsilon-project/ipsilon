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

import sqlite3
import cherrypy
from ipsilon.util.log import Log
import uuid


OPTIONS_COLUMNS = ['name', 'option', 'value']
UNIQUE_DATA_COLUMNS = ['uuid', 'name', 'value']


class Store(Log):

    def __init__(self, config_name):
        if config_name not in cherrypy.config:
            raise NameError('Unknown database type %s' % config_name)
        self._dbname = cherrypy.config[config_name]

    def _build_where(self, kvfilter, kvout):
        where = ""
        sep = "WHERE"
        for k in kvfilter:
            mk = "where_%s" % k
            kvout[mk] = kvfilter[k]
            where += "%s %s=:%s" % (sep, k, mk)
            sep = " AND"
        return where

    def _build_select(self, table, kvfilter=None, kvout=None, columns=None):
        SELECT = "SELECT %(cols)s FROM %(table)s %(where)s"
        cols = "*"
        if columns:
            cols = ",".join(columns)
        where = ""
        if kvfilter is not None:
            where = self._build_where(kvfilter, kvout)
        return SELECT % {'table': table, 'cols': cols, 'where': where}

    def _select(self, cursor, table, kvfilter=None, columns=None):
        kv = dict()
        select = self._build_select(table, kvfilter, kv, columns)
        cursor.execute(select, kv)
        return cursor.fetchall()

    def _create(self, cursor, table, columns):
        CREATE = "CREATE TABLE IF NOT EXISTS %(table)s(%(cols)s)"
        cols = ",".join(columns)
        create = CREATE % {'table': table, 'cols': cols}
        cursor.execute(create)

    def _update(self, cursor, table, values, kvfilter):
        UPDATE = "UPDATE %(table)s SET %(setval)s %(where)s"
        kv = dict()

        setval = ""
        sep = ""
        for k in values:
            mk = "setval_%s" % k
            kv[mk] = values[k]
            setval += "%s%s=:%s" % (sep, k, mk)
            sep = " , "

        where = self._build_where(kvfilter, kv)

        update = UPDATE % {'table': table, 'setval': setval, 'where': where}
        cursor.execute(update, kv)

    def _insert(self, cursor, table, values):
        INSERT = "INSERT INTO %(table)s VALUES(%(values)s)"
        vals = ""
        sep = ""
        for _ in values:
            vals += "%s?" % sep
            sep = ","
        insert = INSERT % {'table': table, 'values': vals}
        cursor.execute(insert, values)

    def _delete(self, cursor, table, kvfilter):
        DELETE = "DELETE FROM %(table)s %(where)s"
        kv = dict()
        where = self._build_where(kvfilter, kv)
        delete = DELETE % {'table': table, 'where': where}
        cursor.execute(delete, kv)

    def _row_to_dict_tree(self, data, row):
        name = row[0]
        if len(row) > 2:
            if name not in data:
                data[name] = dict()
            d2 = data[name]
            self._row_to_dict_tree(d2, row[1:])
        else:
            value = row[1]
            if name in data:
                if data[name] is list:
                    data[name].append(value)
                else:
                    v = data[name]
                    data[name] = [v, value]
            else:
                data[name] = value

    def _rows_to_dict_tree(self, rows):
        data = dict()
        for r in rows:
            self._row_to_dict_tree(data, r)
        return data

    def _load_data(self, table, columns, kvfilter=None):
        con = None
        rows = []
        try:
            con = sqlite3.connect(self._dbname)
            cur = con.cursor()
            self._create(cur, table, columns)
            rows = self._select(cur, table, kvfilter)
            con.commit()
        except sqlite3.Error, e:
            if con:
                con.rollback()
            self.error("Failed to load data for table %s: [%s]" % (table, e))
        finally:
            if con:
                con.close()

        return self._rows_to_dict_tree(rows)

    def load_config(self):
        table = 'config'
        columns = ['name', 'value']
        return self._load_data(table, columns)

    def load_options(self, table, name=None):
        kvfilter = dict()
        if name:
            kvfilter['name'] = name
        options = self._load_data(table, OPTIONS_COLUMNS, kvfilter)
        if name and name in options:
            return options[name]
        return options

    def save_options(self, table, name, options):
        curvals = dict()
        con = None
        try:
            con = sqlite3.connect(self._dbname)
            cur = con.cursor()
            self._create(cur, table, OPTIONS_COLUMNS)
            rows = self._select(cur, table, {'name': name},
                                ['option', 'value'])
            for row in rows:
                curvals[row[0]] = row[1]

            for opt in options:
                if opt in curvals:
                    self._update(cur, table,
                                 {'value': options[opt]},
                                 {'name': name, 'option': opt})
                else:
                    self._insert(cur, table, (name, opt, options[opt]))

            con.commit()
        except sqlite3.Error, e:
            if con:
                con.rollback()
            self.error("Failed to store config: [%s]" % e)
            raise
        finally:
            if con:
                con.close()

    def delete_options(self, table, name, options=None):
        kvfilter = {'name': name}
        try:
            con = sqlite3.connect(self._dbname)
            cur = con.cursor()
            self._create(cur, table, OPTIONS_COLUMNS)
            if options is None:
                self._delete(cur, table, kvfilter)
            else:
                for opt in options:
                    kvfilter['option'] = opt
                    self._delete(cur, table, kvfilter)
            con.commit()
        except sqlite3.Error, e:
            if con:
                con.rollback()
            self.error("Failed to delete from %s: [%s]" % (table, e))
            raise
        finally:
            if con:
                con.close()

    def new_unique_data(self, table, data):
        con = None
        try:
            con = sqlite3.connect(self._dbname)
            cur = con.cursor()
            self._create(cur, table, UNIQUE_DATA_COLUMNS)
            newid = str(uuid.uuid4())
            for name in data:
                self._insert(cur, table, (newid, name, data[name]))
            con.commit()
        except sqlite3.Error, e:
            if con:
                con.rollback()
            cherrypy.log.error("Failed to store %s data: [%s]" % (table, e))
            raise
        finally:
            if con:
                con.close()
        return newid

    def get_unique_data(self, table, uuidval=None, name=None, value=None):
        kvfilter = dict()
        if uuidval:
            kvfilter['uuid'] = uuidval
        if name:
            kvfilter['name'] = name
        if value:
            kvfilter['value'] = value
        return self._load_data(table, UNIQUE_DATA_COLUMNS, kvfilter)

    def save_unique_data(self, table, data):
        curvals = dict()
        con = None
        try:
            con = sqlite3.connect(self._dbname)
            cur = con.cursor()
            self._create(cur, table, UNIQUE_DATA_COLUMNS)
            for uid in data:
                curvals = dict()
                rows = self._select(cur, table, {'uuid': uid},
                                    ['name', 'value'])
                for r in rows:
                    curvals[r[0]] = r[1]

                datum = data[uid]
                for name in datum:
                    if name in curvals:
                        self._update(cur, table,
                                     {'value': datum[name]},
                                     {'uuid': uid, 'name': name})
                    else:
                        self._insert(cur, table, (uid, name, datum[name]))

            con.commit()
        except sqlite3.Error, e:
            if con:
                con.rollback()
            self.error("Failed to store data in %s: [%s]" % (table, e))
            raise
        finally:
            if con:
                con.close()

    def del_unique_data(self, table, uuidval):
        kvfilter = {'uuid': uuidval}
        con = None
        try:
            con = sqlite3.connect(self._dbname)
            cur = con.cursor()
            self._delete(cur, table, kvfilter)
        except sqlite3.Error, e:
            self.error("Failed to delete data from %s: [%s]" % (table, e))
        finally:
            if con:
                con.close()


class AdminStore(Store):

    def __init__(self):
        super(AdminStore, self).__init__('admin.config.db')

    def get_data(self, plugin, idval=None, name=None, value=None):
        return self.get_unique_data(plugin+"_data", idval, name, value)

    def save_data(self, plugin, data):
        return self.save_unique_data(plugin+"_data", data)

    def new_datum(self, plugin, datum):
        table = plugin+"_data"
        return self.new_unique_data(table, datum)

    def del_datum(self, plugin, idval):
        table = plugin+"_data"
        return self.del_unique_data(table, idval)

    def wipe_data(self, plugin):
        table = plugin+"_data"
        # Try to backup old data first, just in case
        try:
            con = sqlite3.connect(self._dbname)
            cur = con.cursor()
            cur.execute("DROP TABLE IF EXISTS " + table)
            self._create(cur, table, UNIQUE_DATA_COLUMNS)
            con.commit()
        except sqlite3.Error, e:
            if con:
                con.rollback()
            cherrypy.log.error("Failed to wipe %s data: [%s]" % (plugin, e))
            raise
        finally:
            if con:
                con.close()


class UserStore(Store):

    def __init__(self, path=None):
        super(UserStore, self).__init__('user.prefs.db')

    def save_user_preferences(self, user, options):
        return self.save_options('users', user, options)


class TranStore(Store):

    def __init__(self, path=None):
        super(TranStore, self).__init__('transactions.db')
