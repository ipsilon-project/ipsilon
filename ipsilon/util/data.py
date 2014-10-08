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

import cherrypy
from ipsilon.util.log import Log
from sqlalchemy import create_engine
from sqlalchemy import MetaData, Table, Column, Text
from sqlalchemy.sql import select
import uuid


OPTIONS_COLUMNS = ['name', 'option', 'value']
UNIQUE_DATA_COLUMNS = ['uuid', 'name', 'value']


class SqlStore(Log):

    def __init__(self, name):
        if name not in cherrypy.config:
            raise NameError('Unknown database %s' % name)
        engine_name = cherrypy.config[name]
        if '://' not in engine_name:
            engine_name = 'sqlite:///' + engine_name
        self._dbengine = create_engine(engine_name)

    def engine(self):
        return self._dbengine

    def connection(self):
        return self._dbengine.connect()


def SqlAutotable(f):
    def at(self, *args, **kwargs):
        if self.autotable:
            self.create()
        return f(self, *args, **kwargs)
    return at


class SqlQuery(Log):

    def __init__(self, db_obj, table, columns, autotable=True, trans=True):
        self._db = db_obj
        self.autotable = autotable
        self._con = self._db.connection()
        self._trans = self._con.begin() if trans else None
        self._table = self._get_table(table, columns)

    def _get_table(self, name, columns):
        table = Table(name, MetaData(self._db.engine()))
        for c in columns:
            table.append_column(Column(c, Text()))
        return table

    def _where(self, kvfilter):
        where = None
        if kvfilter is not None:
            for k in kvfilter:
                w = self._table.columns[k] == kvfilter[k]
                if where is None:
                    where = w
                else:
                    where = where & w
        return where

    def _columns(self, columns=None):
        cols = None
        if columns is not None:
            cols = []
            for c in columns:
                cols.append(self._table.columns[c])
        else:
            cols = self._table.columns
        return cols

    def rollback(self):
        self._trans.rollback()

    def commit(self):
        self._trans.commit()

    def create(self):
        self._table.create(checkfirst=True)

    def drop(self):
        self._table.drop(checkfirst=True)

    @SqlAutotable
    def select(self, kvfilter=None, columns=None):
        return self._con.execute(select(self._columns(columns),
                                        self._where(kvfilter)))

    @SqlAutotable
    def insert(self, values):
        self._con.execute(self._table.insert(values))

    @SqlAutotable
    def update(self, values, kvfilter):
        self._con.execute(self._table.update(self._where(kvfilter), values))

    @SqlAutotable
    def delete(self, kvfilter):
        self._con.execute(self._table.delete(self._where(kvfilter)))


class Store(Log):

    def __init__(self, config_name):
        self._db = SqlStore(config_name)
        self._query = SqlQuery

    def new_query(self, table, columns=None, autotable=True, autocommit=True):
        return self._query(self._db, table, columns, autotable, autocommit)

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

    def load_data(self, table, columns, kvfilter=None):
        rows = []
        try:
            q = self._query(self._db, table, columns, trans=False)
            rows = q.select(kvfilter)
        except Exception, e:  # pylint: disable=broad-except
            self.error("Failed to load data for table %s: [%s]" % (table, e))
        return self._rows_to_dict_tree(rows)

    def load_config(self):
        table = 'config'
        columns = ['name', 'value']
        return self.load_data(table, columns)

    def load_options(self, table, name=None):
        kvfilter = dict()
        if name:
            kvfilter['name'] = name
        options = self.load_data(table, OPTIONS_COLUMNS, kvfilter)
        if name and name in options:
            return options[name]
        return options

    def save_options(self, table, name, options):
        curvals = dict()
        q = None
        try:
            q = self._query(self._db, table, OPTIONS_COLUMNS)
            rows = q.select({'name': name}, ['option', 'value'])
            for row in rows:
                curvals[row[0]] = row[1]

            for opt in options:
                if opt in curvals:
                    q.update({'value': options[opt]},
                             {'name': name, 'option': opt})
                else:
                    q.insert((name, opt, options[opt]))

            q.commit()
        except Exception, e:  # pylint: disable=broad-except
            if q:
                q.rollback()
            self.error("Failed to save options: [%s]" % e)
            raise

    def delete_options(self, table, name, options=None):
        kvfilter = {'name': name}
        q = None
        try:
            q = self._query(self._db, table, OPTIONS_COLUMNS)
            if options is None:
                q.delete(kvfilter)
            else:
                for opt in options:
                    kvfilter['option'] = opt
                    q.delete(kvfilter)
            q.commit()
        except Exception, e:  # pylint: disable=broad-except
            if q:
                q.rollback()
            self.error("Failed to delete from %s: [%s]" % (table, e))
            raise

    def new_unique_data(self, table, data):
        newid = str(uuid.uuid4())
        q = None
        try:
            q = self._query(self._db, table, UNIQUE_DATA_COLUMNS)
            for name in data:
                q.insert((newid, name, data[name]))
            q.commit()
        except Exception, e:  # pylint: disable=broad-except
            if q:
                q.rollback()
            self.error("Failed to store %s data: [%s]" % (table, e))
            raise
        return newid

    def get_unique_data(self, table, uuidval=None, name=None, value=None):
        kvfilter = dict()
        if uuidval:
            kvfilter['uuid'] = uuidval
        if name:
            kvfilter['name'] = name
        if value:
            kvfilter['value'] = value
        return self.load_data(table, UNIQUE_DATA_COLUMNS, kvfilter)

    def save_unique_data(self, table, data):
        q = None
        try:
            q = self._query(self._db, table, UNIQUE_DATA_COLUMNS)
            for uid in data:
                curvals = dict()
                rows = q.select({'uuid': uid}, ['name', 'value'])
                for r in rows:
                    curvals[r[0]] = r[1]

                datum = data[uid]
                for name in datum:
                    if name in curvals:
                        q.update({'value': datum[name]},
                                 {'uuid': uid, 'name': name})
                    else:
                        q.insert((uid, name, datum[name]))

            q.commit()
        except Exception, e:  # pylint: disable=broad-except
            if q:
                q.rollback()
            self.error("Failed to store data in %s: [%s]" % (table, e))
            raise

    def del_unique_data(self, table, uuidval):
        kvfilter = {'uuid': uuidval}
        try:
            q = self._query(self._db, table, UNIQUE_DATA_COLUMNS, trans=False)
            q.delete(kvfilter)
        except Exception, e:  # pylint: disable=broad-except
            self.error("Failed to delete data from %s: [%s]" % (table, e))

    def reset_data(self, table):
        try:
            q = self._query(self._db, table, UNIQUE_DATA_COLUMNS)
            q.drop()
            q.create()
            q.commit()
        except Exception, e:  # pylint: disable=broad-except
            if q:
                q.rollback()
            self.error("Failed to erase all data from %s: [%s]" % (table, e))


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
        self.reset_data(table)


class UserStore(Store):

    def __init__(self, path=None):
        super(UserStore, self).__init__('user.prefs.db')

    def save_user_preferences(self, user, options):
        self.save_options('users', user, options)

    def load_user_preferences(self, user):
        return self.load_options('users', user)

    def save_plugin_data(self, plugin, user, options):
        self.save_options(plugin+"_data", user, options)

    def load_plugin_data(self, plugin, user):
        return self.load_options(plugin+"_data", user)


class TranStore(Store):

    def __init__(self, path=None):
        super(TranStore, self).__init__('transactions.db')
