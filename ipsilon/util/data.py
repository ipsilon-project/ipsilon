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
from sqlalchemy.pool import QueuePool, SingletonThreadPool
from sqlalchemy.sql import select
import ConfigParser
import os
import uuid


OPTIONS_COLUMNS = ['name', 'option', 'value']
UNIQUE_DATA_COLUMNS = ['uuid', 'name', 'value']


class SqlStore(Log):
    __instances = {}

    @classmethod
    def get_connection(cls, name):
        if name not in cls.__instances.keys():
            print 'SqlStore new: %s' % name
            cls.__instances[name] = SqlStore(name)
        return cls.__instances[name]

    def __init__(self, name):
        self.debug('SqlStore init: %s' % name)
        self.name = name
        engine_name = name
        if '://' not in engine_name:
            engine_name = 'sqlite:///' + engine_name
        # This pool size is per configured database. The minimum needed,
        #  determined by binary search, is 23. We're using 25 so we have a bit
        #  more playroom, and then the overflow should make sure things don't
        #  break when we suddenly need more.
        pool_args = {'poolclass': QueuePool,
                     'pool_size': 25,
                     'max_overflow': 50}
        if engine_name.startswith('sqlite://'):
            # It's not possible to share connections for SQLite between
            #  threads, so let's use the SingletonThreadPool for them
            pool_args = {'poolclass': SingletonThreadPool}
        # pylint: disable=star-args
        self._dbengine = create_engine(engine_name, **pool_args)
        self.is_readonly = False

    def engine(self):
        return self._dbengine

    def connection(self):
        self.debug('SqlStore connect: %s' % self.name)
        conn = self._dbengine.connect()

        def cleanup_connection():
            self.debug('SqlStore cleanup: %s' % self.name)
            conn.close()
        cherrypy.request.hooks.attach('on_end_request', cleanup_connection)
        return conn


def SqlAutotable(f):
    def at(self, *args, **kwargs):
        self.create()
        return f(self, *args, **kwargs)
    return at


class SqlQuery(Log):

    def __init__(self, db_obj, table, columns, trans=True):
        self._db = db_obj
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


class FileStore(Log):

    def __init__(self, name):
        self._filename = name
        self.is_readonly = True
        self._timestamp = None
        self._config = None

    def get_config(self):
        try:
            stat = os.stat(self._filename)
        except OSError, e:
            self.error("Unable to check config file %s: [%s]" % (
                self._filename, e))
            self._config = None
            raise
        timestamp = stat.st_mtime
        if self._config is None or timestamp > self._timestamp:
            self._config = ConfigParser.RawConfigParser()
            self._config.optionxform = str
            self._config.read(self._filename)
        return self._config


class FileQuery(Log):

    def __init__(self, fstore, table, columns, trans=True):
        self._fstore = fstore
        self._config = fstore.get_config()
        self._section = table
        if len(columns) > 3 or columns[-1] != 'value':
            raise ValueError('Unsupported configuration format')
        self._columns = columns

    def rollback(self):
        return

    def commit(self):
        return

    def create(self):
        raise NotImplementedError

    def drop(self):
        raise NotImplementedError

    def select(self, kvfilter=None, columns=None):
        if self._section not in self._config.sections():
            return []

        opts = self._config.options(self._section)

        prefix = None
        prefix_ = ''
        if self._columns[0] in kvfilter:
            prefix = kvfilter[self._columns[0]]
            prefix_ = prefix + ' '

        name = None
        if len(self._columns) == 3 and self._columns[1] in kvfilter:
            name = kvfilter[self._columns[1]]

        value = None
        if self._columns[-1] in kvfilter:
            value = kvfilter[self._columns[-1]]

        res = []
        for o in opts:
            if len(self._columns) == 3:
                # 3 cols
                if prefix and not o.startswith(prefix_):
                    continue

                col1, col2 = o.split(' ', 1)
                if name and col2 != name:
                    continue

                col3 = self._config.get(self._section, o)
                if value and col3 != value:
                    continue

                r = [col1, col2, col3]
            else:
                # 2 cols
                if prefix and o != prefix:
                    continue
                r = [o, self._config.get(self._section, o)]

            if columns:
                s = []
                for c in columns:
                    s.append(r[self._columns.index(c)])
                res.append(s)
            else:
                res.append(r)

        self.debug('SELECT(%s, %s, %s) -> %s' % (self._section,
                                                 repr(kvfilter),
                                                 repr(columns),
                                                 repr(res)))
        return res

    def insert(self, values):
        raise NotImplementedError

    def update(self, values, kvfilter):
        raise NotImplementedError

    def delete(self, kvfilter):
        raise NotImplementedError


class Store(Log):
    def __init__(self, config_name=None, database_url=None):
        if config_name is None and database_url is None:
            raise ValueError('config_name or database_url must be provided')
        if config_name:
            if config_name not in cherrypy.config:
                raise NameError('Unknown database %s' % config_name)
            name = cherrypy.config[config_name]
        else:
            name = database_url
        if name.startswith('configfile://'):
            _, filename = name.split('://')
            self._db = FileStore(filename)
            self._query = FileQuery
        else:
            self._db = SqlStore.get_connection(name)
            self._query = SqlQuery

    @property
    def is_readonly(self):
        return self._db.is_readonly

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
        return self._load_data(table, UNIQUE_DATA_COLUMNS, kvfilter)

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
                        if datum[name] is None:
                            q.delete({'uuid': uid, 'name': name})
                        else:
                            q.update({'value': datum[name]},
                                     {'uuid': uid, 'name': name})
                    else:
                        if datum[name] is not None:
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

    def _reset_data(self, table):
        q = None
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
        self._reset_data(table)


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
