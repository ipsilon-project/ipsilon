# Copyright (C) 2013 Ipsilon project Contributors, for license see COPYING

import cherrypy
import datetime
from ipsilon.util.log import Log
from sqlalchemy import create_engine
from sqlalchemy import MetaData, Table, Column, Text
from sqlalchemy.pool import QueuePool, SingletonThreadPool
from sqlalchemy.schema import (PrimaryKeyConstraint, Index, AddConstraint,
                               CreateIndex)
from sqlalchemy.sql import select, and_
import ConfigParser
import os
import uuid
import logging
import time


CURRENT_SCHEMA_VERSION = 2
OPTIONS_TABLE = {'columns': ['name', 'option', 'value'],
                 'primary_key': ('name', 'option'),
                 'indexes': [('name',)]
                 }
UNIQUE_DATA_TABLE = {'columns': ['uuid', 'name', 'value'],
                     'primary_key': ('uuid', 'name'),
                     'indexes': [('uuid',)]
                     }


class DatabaseError(Exception):
    pass


class BaseStore(Log):
    # Some helper functions used for upgrades
    def add_constraint(self, table):
        raise NotImplementedError()

    def add_index(self, index):
        raise NotImplementedError()


class SqlStore(BaseStore):
    __instances = {}

    @classmethod
    def get_connection(cls, name):
        if name not in cls.__instances:
            if cherrypy.config.get('db.conn.log', False):
                logging.debug('SqlStore new: %s', name)
            cls.__instances[name] = SqlStore(name)
        return cls.__instances[name]

    def __init__(self, name):
        self.db_conn_log = cherrypy.config.get('db.conn.log', False)
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
        self._dbengine = create_engine(engine_name,
                                       echo=cherrypy.config.get('db.echo',
                                                                False),
                                       **pool_args)
        self.is_readonly = False

    def add_constraint(self, constraint):
        if self._dbengine.dialect.name != 'sqlite':
            # It is impossible to add constraints to a pre-existing table for
            #  SQLite
            # source: http://www.sqlite.org/omitted.html
            create_constraint = AddConstraint(constraint, bind=self._dbengine)
            create_constraint.execute()

    def add_index(self, index):
        add_index = CreateIndex(index, bind=self._dbengine)
        add_index.execute()

    def debug(self, fact):
        if self.db_conn_log:
            super(SqlStore, self).debug(fact)

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


class SqlQuery(Log):

    def __init__(self, db_obj, table, table_def, trans=True):
        self._db = db_obj
        self._con = self._db.connection()
        self._trans = self._con.begin() if trans else None
        self._table = self._get_table(table, table_def)

    def _get_table(self, name, table_def):
        if isinstance(table_def, list):
            table_def = {'columns': table_def,
                         'indexes': [],
                         'primary_key': None}
        table_creation = []
        for col_name in table_def['columns']:
            table_creation.append(Column(col_name, Text()))
        if table_def['primary_key']:
            table_creation.append(PrimaryKeyConstraint(
                *table_def['primary_key']))
        for index in table_def['indexes']:
            idx_name = 'idx_%s_%s' % (name, '_'.join(index))
            table_creation.append(Index(idx_name, *index))
        table = Table(name, MetaData(self._db.engine()), *table_creation)
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

    def select(self, kvfilter=None, columns=None):
        return self._con.execute(select(self._columns(columns),
                                        self._where(kvfilter)))

    def insert(self, values):
        self._con.execute(self._table.insert(values))

    def update(self, values, kvfilter):
        self._con.execute(self._table.update(self._where(kvfilter), values))

    def delete(self, kvfilter):
        self._con.execute(self._table.delete(self._where(kvfilter)))


class FileStore(BaseStore):

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

    def add_constraint(self, table):
        raise NotImplementedError()

    def add_index(self, index):
        raise NotImplementedError()


class FileQuery(Log):

    def __init__(self, fstore, table, table_def, trans=True):
        # We don't need indexes in a FileQuery, so drop that info
        if isinstance(table_def, dict):
            columns = table_def['columns']
        else:
            columns = table_def
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
    # Static, Store-level variables
    _is_upgrade = False
    __cleanups = {}

    # Static, class-level variables
    # Either set this to False, or implement _cleanup, in child classes
    _should_cleanup = True

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

        if not self._is_upgrade:
            self._check_database()
            if self._should_cleanup:
                self._schedule_cleanup()

    def _schedule_cleanup(self):
        store_name = self.__class__.__name__
        if self.is_readonly:
            # No use in cleanups on a readonly database
            self.debug('Not scheduling cleanup for %s due to readonly' %
                       store_name)
            return
        if store_name in Store.__cleanups:
            # This class was already scheduled, skip
            return
        self.debug('Scheduling cleanups for %s' % store_name)
        # Check once every minute whether we need to clean
        task = cherrypy.process.plugins.BackgroundTask(
            60, self._maybe_run_cleanup)
        task.start()
        Store.__cleanups[store_name] = task

    def _maybe_run_cleanup(self):
        # Let's see if we need to do cleanup
        last_clean = self.load_options('dbinfo').get('%s_last_clean' %
                                                     self.__class__.__name__,
                                                     {})
        time_diff = cherrypy.config.get('cleanup_interval', 30) * 60
        next_ts = int(time.time()) - time_diff
        self.debug('Considering cleanup for %s: %s. Next at: %s'
                   % (self.__class__.__name__, last_clean, next_ts))
        if ('timestamp' not in last_clean or
                int(last_clean['timestamp']) <= next_ts):
            # First store the current time so that other servers don't start
            self.save_options('dbinfo', '%s_last_clean'
                              % self.__class__.__name__,
                              {'timestamp': int(time.time()),
                               'removed_entries': -1})

            # Cleanup has been long enough ago, let's run
            self.debug('Cleaning up for %s' % self.__class__.__name__)
            removed_entries = self._cleanup()
            self.debug('Cleaned up %i entries for %s' %
                       (removed_entries, self.__class__.__name__))
            self.save_options('dbinfo', '%s_last_clean'
                              % self.__class__.__name__,
                              {'timestamp': int(time.time()),
                               'removed_entries': removed_entries})

    def _cleanup(self):
        # The default cleanup is to do nothing
        # This function should return the number of rows it cleaned up.
        # This information may be used to automatically tune the clean period.
        self.error('Cleanup for %s not implemented' %
                   self.__class__.__name__)
        return 0

    def _code_schema_version(self):
        # This function makes it possible for separate plugins to have
        #  different schema versions. We default to the global schema
        #  version.
        return CURRENT_SCHEMA_VERSION

    def _get_schema_version(self):
        # We are storing multiple versions: one per class
        # That way, we can support plugins with differing schema versions from
        #  the main codebase, and even in the same database.
        q = self._query(self._db, 'dbinfo', OPTIONS_TABLE, trans=False)
        q.create()
        q._con.close()  # pylint: disable=protected-access
        cls_name = self.__class__.__name__
        current_version = self.load_options('dbinfo').get('%s_schema'
                                                          % cls_name, {})
        if 'version' in current_version:
            return int(current_version['version'])
        else:
            # Also try the old table name.
            # "scheme" was a typo, but we need to retain that now for compat
            fallback_version = self.load_options('dbinfo').get('scheme',
                                                               {})
            if 'version' in fallback_version:
                # Explanation for this is in def upgrade_database(self)
                return -1
            else:
                return None

    def _check_database(self):
        if self.is_readonly:
            # If the database is readonly, we cannot do anything to the
            #  schema. Let's just return, and assume people checked the
            #  upgrade notes
            return

        current_version = self._get_schema_version()
        if current_version is None:
            self.error('Database initialization required! ' +
                       'Please run ipsilon-upgrade-database')
            raise DatabaseError('Database initialization required for %s' %
                                self.__class__.__name__)
        if current_version != self._code_schema_version():
            self.error('Database upgrade required! ' +
                       'Please run ipsilon-upgrade-database')
            raise DatabaseError('Database upgrade required for %s' %
                                self.__class__.__name__)

    def _store_new_schema_version(self, new_version):
        cls_name = self.__class__.__name__
        self.save_options('dbinfo', '%s_schema' % cls_name,
                          {'version': new_version})

    def _initialize_schema(self):
        raise NotImplementedError()

    def _upgrade_schema(self, old_version):
        # Datastores need to figure out what to do with bigger old_versions
        #  themselves.
        # They might implement downgrading if that's feasible, or just throw
        #  NotImplementedError
        # Should return the new schema version
        raise NotImplementedError()

    def upgrade_database(self):
        # Do whatever is needed to get schema to current version
        old_schema_version = self._get_schema_version()
        if old_schema_version is None:
            # Just initialize a new schema
            self._initialize_schema()
            self._store_new_schema_version(self._code_schema_version())
        elif old_schema_version == -1:
            # This is a special-case from 1.0: we only created tables at the
            # first time they were actually used, but the upgrade code assumes
            # that the tables exist. So let's fix this.
            self._initialize_schema()
            # The old version was schema version 1
            self._store_new_schema_version(1)
            self.upgrade_database()
        elif old_schema_version != self._code_schema_version():
            # Upgrade from old_schema_version to code_schema_version
            self.debug('Upgrading from schema version %i' % old_schema_version)
            new_version = self._upgrade_schema(old_schema_version)
            if not new_version:
                error = ('Schema upgrade error: %s did not provide a ' +
                         'new schema version number!' %
                         self.__class__.__name__)
                self.error(error)
                raise Exception(error)
            self._store_new_schema_version(new_version)
            # Check if we are now up-to-date
            self.upgrade_database()

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
            self.error("Failed to load data for table %s for store %s: [%s]"
                       % (table, self.__class__.__name__, e))
        return self._rows_to_dict_tree(rows)

    def load_config(self):
        table = 'config'
        columns = ['name', 'value']
        return self._load_data(table, columns)

    def load_options(self, table, name=None):
        kvfilter = dict()
        if name:
            kvfilter['name'] = name
        options = self._load_data(table, OPTIONS_TABLE, kvfilter)
        if name and name in options:
            return options[name]
        return options

    def save_options(self, table, name, options):
        curvals = dict()
        q = None
        try:
            q = self._query(self._db, table, OPTIONS_TABLE)
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
            q = self._query(self._db, table, OPTIONS_TABLE)
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
            q = self._query(self._db, table, UNIQUE_DATA_TABLE)
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
        return self._load_data(table, UNIQUE_DATA_TABLE, kvfilter)

    def save_unique_data(self, table, data):
        q = None
        try:
            q = self._query(self._db, table, UNIQUE_DATA_TABLE)
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
            q = self._query(self._db, table, UNIQUE_DATA_TABLE, trans=False)
            q.delete(kvfilter)
        except Exception, e:  # pylint: disable=broad-except
            self.error("Failed to delete data from %s: [%s]" % (table, e))

    def _reset_data(self, table):
        q = None
        try:
            q = self._query(self._db, table, UNIQUE_DATA_TABLE)
            q.drop()
            q.create()
            q.commit()
        except Exception, e:  # pylint: disable=broad-except
            if q:
                q.rollback()
            self.error("Failed to erase all data from %s: [%s]" % (table, e))


class AdminStore(Store):
    _should_cleanup = False

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

    def _initialize_schema(self):
        for table in ['config',
                      'info_config',
                      'login_config',
                      'provider_config']:
            q = self._query(self._db, table, OPTIONS_TABLE, trans=False)
            q.create()
            q._con.close()  # pylint: disable=protected-access

    def _upgrade_schema(self, old_version):
        if old_version == 1:
            # In schema version 2, we added indexes and primary keys
            for table in ['config',
                          'info_config',
                          'login_config',
                          'provider_config']:
                # pylint: disable=protected-access
                table = self._query(self._db, table, OPTIONS_TABLE,
                                    trans=False)._table
                self._db.add_constraint(table.primary_key)
                for index in table.indexes:
                    self._db.add_index(index)
            return 2
        else:
            raise NotImplementedError()

    def create_plugin_data_table(self, plugin_name):
        if not self.is_readonly:
            table = plugin_name+'_data'
            q = self._query(self._db, table, UNIQUE_DATA_TABLE,
                            trans=False)
            q.create()
            q._con.close()  # pylint: disable=protected-access


class UserStore(Store):
    _should_cleanup = False

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

    def _initialize_schema(self):
        q = self._query(self._db, 'users', OPTIONS_TABLE, trans=False)
        q.create()
        q._con.close()  # pylint: disable=protected-access

    def _upgrade_schema(self, old_version):
        if old_version == 1:
            # In schema version 2, we added indexes and primary keys
            # pylint: disable=protected-access
            table = self._query(self._db, 'users', OPTIONS_TABLE,
                                trans=False)._table
            self._db.add_constraint(table.primary_key)
            for index in table.indexes:
                self._db.add_index(index)
            return 2
        else:
            raise NotImplementedError()


class TranStore(Store):

    def __init__(self, path=None):
        super(TranStore, self).__init__('transactions.db')
        self.table = 'transactions'

    def _initialize_schema(self):
        q = self._query(self._db, self.table, UNIQUE_DATA_TABLE,
                        trans=False)
        q.create()
        q._con.close()  # pylint: disable=protected-access

    def _upgrade_schema(self, old_version):
        if old_version == 1:
            # In schema version 2, we added indexes and primary keys
            # pylint: disable=protected-access
            table = self._query(self._db, self.table, UNIQUE_DATA_TABLE,
                                trans=False)._table
            self._db.add_constraint(table.primary_key)
            for index in table.indexes:
                self._db.add_index(index)
            return 2
        else:
            raise NotImplementedError()

    def _cleanup(self):
        # pylint: disable=protected-access
        table = SqlQuery(self._db, self.table, UNIQUE_DATA_TABLE)._table
        in_one_hour = datetime.datetime.now() - datetime.timedelta(hours=1)
        sel = select([table.columns.uuid]). \
            where(and_(table.c.name == 'origintime',
                       table.c.value <= in_one_hour))
        # pylint: disable=no-value-for-parameter
        d = table.delete().where(table.c.uuid.in_(sel))
        return d.execute().rowcount


class SAML2SessionStore(Store):

    def __init__(self, database_url):
        super(SAML2SessionStore, self).__init__(database_url=database_url)
        self.table = 'saml2_sessions'
        # pylint: disable=protected-access
        table = SqlQuery(self._db, self.table, UNIQUE_DATA_TABLE)._table
        table.create(checkfirst=True)

    def _get_unique_id_from_column(self, name, value):
        """
        The query is going to return only the column in the query.
        Use this method to get the uuidval which can be used to fetch
        the entire entry.

        Returns None or the uuid of the first value found.
        """
        data = self.get_unique_data(self.table, name=name, value=value)
        count = len(data)
        if count == 0:
            return None
        elif count != 1:
            raise ValueError("Multiple entries returned")
        return data.keys()[0]

    def _cleanup(self):
        # pylint: disable=protected-access
        table = SqlQuery(self._db, self.table, UNIQUE_DATA_TABLE)._table
        sel = select([table.columns.uuid]). \
            where(and_(table.c.name == 'expiration_time',
                       table.c.value <= datetime.datetime.now()))
        # pylint: disable=no-value-for-parameter
        d = table.delete().where(table.c.uuid.in_(sel))
        return d.execute().rowcount

    def get_data(self, idval=None, name=None, value=None):
        return self.get_unique_data(self.table, idval, name, value)

    def new_session(self, datum):
        if 'supported_logout_mechs' in datum:
            datum['supported_logout_mechs'] = ','.join(
                datum['supported_logout_mechs']
            )
        return self.new_unique_data(self.table, datum)

    def get_session(self, session_id=None, request_id=None):
        if session_id:
            uuidval = self._get_unique_id_from_column('session_id', session_id)
        elif request_id:
            uuidval = self._get_unique_id_from_column('request_id', request_id)
        else:
            raise ValueError("Unable to find session")
        if not uuidval:
            return None, None
        data = self.get_unique_data(self.table, uuidval=uuidval)
        return uuidval, data[uuidval]

    def get_user_sessions(self, user):
        """
        Return a list of all sessions for a given user.
        """
        rows = self.get_unique_data(self.table, name='user', value=user)

        # We have a list of sessions for this user, now get the details
        logged_in = []
        for r in rows:
            data = self.get_unique_data(self.table, uuidval=r)
            data[r]['supported_logout_mechs'] = data[r].get(
                'supported_logout_mechs', '').split(',')
            logged_in.append(data)

        return logged_in

    def update_session(self, datum):
        self.save_unique_data(self.table, datum)

    def remove_session(self, uuidval):
        self.del_unique_data(self.table, uuidval)

    def wipe_data(self):
        self._reset_data(self.table)

    def _initialize_schema(self):
        q = self._query(self._db, self.table, UNIQUE_DATA_TABLE,
                        trans=False)
        q.create()
        q._con.close()  # pylint: disable=protected-access

    def _upgrade_schema(self, old_version):
        if old_version == 1:
            # In schema version 2, we added indexes and primary keys
            # pylint: disable=protected-access
            table = self._query(self._db, self.table, UNIQUE_DATA_TABLE,
                                trans=False)._table
            self._db.add_constraint(table.primary_key)
            for index in table.indexes:
                self._db.add_index(index)
            return 2
        else:
            raise NotImplementedError()
