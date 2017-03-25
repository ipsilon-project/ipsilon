# Copyright (C) 2013 Ipsilon project Contributors, for license see COPYING

import cherrypy
import datetime
from ipsilon.util.log import Log
from sqlalchemy import create_engine
from sqlalchemy import MetaData, Table, Column, Text, String
from sqlalchemy.pool import QueuePool, SingletonThreadPool
from sqlalchemy.schema import (PrimaryKeyConstraint, Index, AddConstraint,
                               CreateIndex)
from sqlalchemy.sql import select, and_
import ConfigParser
try:
    import etcd
except ImportError:
    etcd = None
import os
import json
import uuid
from urlparse import urlparse
import logging
import time


CURRENT_SCHEMA_VERSION = 3
OPTIONS_TABLE = {'columns': [('name', String(255)), ('option', String(255)),
                             ('value', Text())],
                 'primary_key': ('name', 'option'),
                 'indexes': [('name',)]
                 }
UNIQUE_DATA_TABLE = {'columns': [('uuid', String(255)), ('name', String(255)),
                                 ('value', Text())],
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
    def get_instance(cls, name):
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

    def connection(self, will_close=False):
        """Function that makes a connection to the database.

        will_close indicates whether the client will take responsibility of
        closing the connection after it's done with it."""
        self.debug('SqlStore connect: %s' % self.name)
        conn = self._dbengine.connect()

        def cleanup_connection():
            self.debug('SqlStore cleanup: %s' % self.name)
            conn.close()
        if not will_close:
            cherrypy.request.hooks.attach('on_end_request', cleanup_connection)
        return conn


class BaseQuery(Log):

    def commit(self):
        """Function to override to commit the transaction."""
        pass

    def rollback(self):
        """Function to override to roll the transaction back."""
        pass

    def _setup_connection(self):
        """Function to override to get a transaction and connection."""
        pass

    def _teardown_connection(self):
        """Function to override to close transactions and connections."""
        pass

    def __enter__(self):
        """Context Manager enter method.

        This calls the setup connections method.
        """
        self._setup_connection()
        return self

    def __exit__(self, exc_class, exc, tb):
        """ Context Manager exit method.

        This automatically rolls back the transaction if an error occured and
        the engine supports it, and otherwise runs the database commit method.
        After this, it will run the teardown method.

        All the arguments are defined by PEP#343.
        """
        if exc is None:
            self.commit()
        else:
            self.rollback()
        self._teardown_connection()


class SqlQuery(BaseQuery):

    def __init__(self, db_obj, table, table_def, trans=True):
        self._db = db_obj
        self.__con = None
        self._trans = None
        self._use_trans = trans
        self._table = self._get_table(table, table_def)

    def _setup_connection(self):
        self.__con = self._db.connection(True)
        self._trans = self._con.begin() if self._use_trans else None

    def _teardown_connection(self):
        self.__con.close()
        self.__con = None
        self._trans = None

    @property
    def _con(self):
        """Function that makes sure there is an active connection.

        This is for backwards compatibility if other classes use SqlQuery
        without the context manager handling."""
        if not self.__con:
            self.error('DEPRECATED: SqlQuery used without context manager!')
            # Since we will not get notified when the user is done, we will
            # need to get the conn closed after the request.
            self.__con = self._db.connection(will_close=False)
            self._trans = self._con.begin() if self._use_trans else None
        return self.__con

    def _get_table(self, name, table_def):
        if isinstance(table_def, list):
            table_def = {'columns': table_def,
                         'indexes': [],
                         'primary_key': None}
        table_creation = []
        for col_def in table_def['columns']:
            if not isinstance(col_def, tuple):
                col_def = (col_def, Text())
            col = Column(col_def[0], col_def[1])
            table_creation.append(col)
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
                w = self._table.c[k] == kvfilter[k]
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
                cols.append(self._table.c[c])
        else:
            cols = self._table.columns
        return cols

    def rollback(self):
        if not self._trans:
            return
        self._trans.rollback()

    def commit(self):
        if not self._trans:
            return
        self._trans.commit()

    def create(self):
        self._table.create(checkfirst=True)

    def drop(self):
        self._table.drop(checkfirst=True)

    def select(self, kvfilter=None, columns=None):
        return self._con.execute(select(self._columns(columns),
                                        self._where(kvfilter)))

    def insert(self, values, ttl=None):
        self._con.execute(self._table.insert(values))

    def update(self, values, kvfilter):
        self._con.execute(self._table.update(self._where(kvfilter), values))

    def delete(self, kvfilter):
        self._con.execute(self._table.delete(self._where(kvfilter)))

    def perform_auto_cleanup(self):
        table = self._table
        sel = select([table.c.uuid]). \
            where(and_(table.c.name == 'expiration_time',
                       table.c.value <= str(datetime.datetime.now())))
        # pylint: disable=no-value-for-parameter
        d = table.delete().where(table.c.uuid.in_(sel))
        return d.execute().rowcount


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


class FileQuery(BaseQuery):

    def __init__(self, fstore, table, table_def, trans=True):
        # We don't need indexes in a FileQuery, so drop that info
        if isinstance(table_def, dict):
            columns = table_def['columns']
            if isinstance(columns[0], tuple):
                columns = [column[0] for column in columns]
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

    def insert(self, values, ttl=None):
        raise NotImplementedError

    def update(self, values, kvfilter):
        raise NotImplementedError

    def delete(self, kvfilter):
        raise NotImplementedError

    def perform_auto_cleanup(self):
        raise NotImplementedError


class EtcdStore(BaseStore):
    """Etcd-based storage

    Example URI: etcd://server/rootpath?port=2379&scheme=https
    The rootpath indicates at what point in the etcd key-space we will insert
    our keys.
    The parts after the ? are passed as key-value to the etcd client.
    """

    def __init__(self, uri):
        if etcd is None:
            raise NotImplementedError('Etcd client not available')
        url = urlparse(uri)
        self.rootpath = url.path
        config = dict([cfg.split('=', 1) for cfg in url.query.split('&')])

        if 'port' in config:
            config['port'] = int(config['port'])

        self.debug('Etcd host: %s, rootpath: %s, config: %s' %
                   (url.netloc, url.path, config))

        self.client = etcd.Client(host=url.netloc, **config)

        # We ignore the value, but this is a connection test
        self.client.leader  # pylint: disable=pointless-statement

        self.is_readonly = False

    def add_constraint(self, table):
        raise NotImplementedError()

    def add_index(self, index):
        raise NotImplementedError()

    def close(self):
        # No-op
        return


class EtcdQuery(BaseQuery):
    """
    Class to store stuff in Etcd key-value stores.

    A row is stored in the etcd store under
    /<rootpath>/<table>/<pk_1>/<pk_2>/.../<pk_n>
    Where rootpath is configurable, <table> is the name of the name of the
    table, and pk_1, pk_2, ..., pk_n are the first, second and nth components
    of the primary key of that table.

    This means that tables using etcd require a primary key.

    The value stored at those keys is a json document with all of the keys and
    values for that object, including the primary keys.

    Cleanup of objects in etcd we leave to Etcd: when the object gets created,
    we store the TTL in the key.
    """

    def __init__(self, store, table, table_def, trans=True):
        """Query class initialization.

        store is a handle to a connected EtcdStore object.
        table is the name of the "table" (key space) we are querying.
        table_def is the table definition, look at OPTIONS_TABLE and
            UNIQUE_DATA_TABLE for examples.
        trans is accepted for compatibility with other Query types, but
            ignored.
        """
        if etcd is None:
            raise NotImplementedError('Etcd client not available')
        # We don't have indexes in a EtcdQuery, so drop that info
        if isinstance(table_def, dict) and 'primary_key' in table_def:
            columns = table_def['columns']
            if isinstance(columns[0], tuple):
                columns = [column[0] for column in columns]
            self._primary_key = tuple(table_def['primary_key'])
        else:
            # This is a custom plugin that uses tables that are incompatible
            # with etcd.
            raise ValueError('Etcd requires primary key')
        self._table = table
        self._table_def = table_def
        self._store = store
        self._section = table
        self._columns = columns
        self._con = store

    @property
    def _table_dir(self):
        """This returns the full path to the table key."""
        return '%s/%s' % (self._store.rootpath, self._table)

    def _get_most_specific_dir(self, kvfilter, del_kv=True, update=False):
        """Get the most specific dir in which we can find stuff.

        Return a tuple with path and then the number of path levels not used.

        kvfilter is a dict with the keys we want to filter for.
        del_kv is a boolean that indicates whether or not to remove used
            filters from the kvfilter dict.
        update is a boolean that indicates whether this is for an insert/update
            operation. Those require a fully specified object path.
        """
        path = self._table_dir

        if kvfilter is None:
            kvfilter = {}

        pkeys_used = 0
        # We try to use as much of the primary key as we are able to to
        # generate the most specific path possible.
        for pkey in self._primary_key:
            if pkey in kvfilter:
                pkeys_used += 1
                path = os.path.join(path, kvfilter[pkey].replace(' ', '_'))
                if del_kv:
                    del kvfilter[pkey]
            else:
                # Seems this next primary key value was not part of the filter
                break

        levels_unused = len(self._primary_key) - pkeys_used

        if levels_unused != 0 and update:
            raise Exception('Fully qualified object required for updates')

        return path, levels_unused

    def rollback(self):
        """Rollback is ignored because etcd doesn't have transactions."""
        return

    def commit(self):
        """Commit is ignored because etcd doesn't have transactions."""
        return

    def create(self):
        """Create a directory to store the current table in."""
        try:
            self._store.client.write(self._table_dir, None, dir=True)
        except etcd.EtcdNotFile:
            # This means that this key already contained a directory. In which
            # case, we are done.
            pass

    def drop(self):
        """Drop the current table and everything under it."""
        self._store.client.delete(self._table_dir, recursive=True, dir=True)

    def _select_objects(self, kvfilter):
        """
        Select all the objects that satisfy the kvfilter parts that are in the
        primary key for this table.
        """
        path, levels_unused = self._get_most_specific_dir(kvfilter)
        try:
            res = self._store.client.read(path, recursive=levels_unused != 0)
        except etcd.EtcdKeyNotFound:
            return None

        if levels_unused == 0:
            # This was a fully qualified object, let's use the object
            if res.dir:
                return []
            else:
                return [res]
        else:
            # This was not fully qualified. Given we used recursive=True, we
            # know that "children" is the final objects.
            return [cld for cld in res.children if not cld.dir]

    def _select_filter(self, kvfilter, res):
        """
        Filters all objects from res that do not satisfy the non-primary
        kvfilter entries.
        """
        for obj in res:
            result = json.loads(obj.value)

            pick_object = True
            for key in kvfilter:
                if key not in result:
                    pick_object = False
                    break
                if result[key] != kvfilter[key]:
                    pick_object = False
                    break
            if pick_object:
                yield result

    def select(self, kvfilter=None, columns=None):
        """Select specific objects from the store.

        kvfilter is a dict indicating which keys should be matched for.
        columns is a list of columns to return, and their order.
        Returns a list of column value lists.
        """
        if columns is None:
            columns = self._columns

        res = self._select_objects(kvfilter)
        if res is None:
            return []
        results = self._select_filter(kvfilter, res)

        rows = []
        for obj in results:
            row = []
            for column in columns:
                row.append(obj[column])
            rows.append(tuple(row))

        return rows

    def insert(self, value_row, ttl=None):
        """Insert a new object into the store.

        value_row is a list of column values.
        ttl is the time for which the object is supposed to be kept.
        """
        value_row = list(value_row)

        values = {}
        for column in self._columns:
            values[column] = value_row.pop(0)

        path, _ = self._get_most_specific_dir(values, False, update=True)
        self._store.client.write(path, json.dumps(values), ttl=ttl)

    def update(self, values, kvfilter):
        """Updates an item in the store.

        Requires a single object, thus the kvfilter must be specific to match
        a single object.

        kvfilter is the dict of key-values that find a specific object.
        values is the dict with key-values that we want to update to.
        """
        path, _ = self._get_most_specific_dir(kvfilter, update=True)
        for key in values:
            if key in self._primary_key:
                raise ValueError('Unable to update primary key values')

        current = json.loads(self._store.client.read(path).value)
        for key in values:
            current[key] = values[key]
        self._store.client.write(path, json.dumps(current))

    def delete(self, kvfilter):
        """Deletes an item from the store.

        Requires a single object, thus the kvfilter must be specific to match
        a single object.

        kvfilter is the dict of key-values that find a specific object.
        """
        path, levels_unused = self._get_most_specific_dir(kvfilter)
        if levels_unused == 0 or len(kvfilter) == 0:
            try:
                current = json.loads(self._store.client.read(path).value)
            except etcd.EtcdKeyNotFound:
                return
            for key in kvfilter:
                if current[key] != kvfilter[key]:
                    # We had 0 levels unused, meaning we are at a qualified
                    # object, and it doesn't match the kvfilter. We are done.
                    return
            try:
                self._store.client.delete(path, recursive=True, dir=True)
            except etcd.EtcdKeyNotFound:
                pass
        else:
            # This was not a fully specified object, we need to get all fully
            # qualified objects
            raise NotImplementedError()


class Store(Log):
    # Static, Store-level variables
    _is_upgrade = False
    __cleanups = {}

    # Static, class-level variables
    # Either set this to False, or implement cleanup
    # The two methods for cleanup are:
    # - Implement a method _cleanup in the child class
    # - Set _auto_cleanups to a list of UNIQUE_DATA tables
    _should_cleanup = True
    _auto_cleanup_tables = []

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
        elif name.startswith('etcd://'):
            self._db = EtcdStore(name)
            self._query = EtcdQuery
        else:
            self._db = SqlStore.get_instance(name)
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
            self.debug('Starting autoclean for %s' % self.__class__.__name__)
            auto_removed_entries = self._auto_cleanup()
            self.debug('Auto-cleaned up %i entries for %s' %
                       (auto_removed_entries, self.__class__.__name__))

            self.debug('Cleaning up for %s' % self.__class__.__name__)
            removed_entries = self._cleanup()
            self.debug('Cleaned up %i entries for %s' %
                       (removed_entries, self.__class__.__name__))
            self.save_options('dbinfo', '%s_last_clean'
                              % self.__class__.__name__,
                              {'timestamp': int(time.time()),
                               'removed_entries': removed_entries})

    def _auto_cleanup(self):
        # This function runs an automated cleanup for all subclasses that have
        # set some auto_cleanup_tables. This requires that the tables mentioned
        # use the standard UNIQUE_DATA_TABLE system, and they specify either an
        # expiration_time or a ttl to new_unique_data.
        cleaned = 0
        for table in self._auto_cleanup_tables:
            self.debug('Auto-cleaning %s' % table)
            q = self._query(self._db, table, UNIQUE_DATA_TABLE)
            cleaned_table = q.perform_auto_cleanup()
            self.debug('Cleaned up %i entries' % cleaned_table)
            cleaned += cleaned_table
        return cleaned

    def _cleanup(self):
        # The default cleanup is to do nothing
        # This function should return the number of rows it cleaned up.
        # This information may be used to automatically tune the clean period.
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

        base = cherrypy.config.get('base.mount', '/')
        if base == '/':
            updbargs = '--root-instance'
        else:
            updbargs = '--instance %s' % base[1:]

        if current_version is None:
            self.error('Database initialization required! ' +
                       'Please run ipsilon-upgrade-database ' + updbargs)
            raise DatabaseError('Database initialization required for %s' %
                                self.__class__.__name__)
        if current_version != self._code_schema_version():
            self.error('Database upgrade required! ' +
                       'Please run ipsilon-upgrade-database ' + updbargs)
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
        return self._load_data(table, OPTIONS_TABLE)

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

            for opt in curvals:
                if opt not in options:
                    q.delete({'name': name, 'option': opt})

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

    def new_unique_data(self, table, data, ttl=None, expiration_time=None):
        if expiration_time:
            ttl = expiration_time - int(time.time())
        elif ttl:
            expiration_time = int(time.time()) + ttl
        if ttl and ttl < 0:
            raise ValueError('Negative TTL specified: %s' % ttl)

        newid = str(uuid.uuid4())
        q = None
        try:
            q = self._query(self._db, table, UNIQUE_DATA_TABLE)
            for name in data:
                q.insert((newid, name, data[name]), ttl)
            if expiration_time:
                q.insert((newid, 'expiration_time', expiration_time), ttl)
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

    def save_unique_data(self, table, data, ttl=None, expiration_time=None):
        if expiration_time:
            ttl = expiration_time - int(time.time())
        elif ttl:
            expiration_time = int(time.time()) + ttl
        if ttl and ttl < 0:
            raise ValueError('Negative TTL specified: %s' % ttl)

        q = None
        try:
            q = self._query(self._db, table, UNIQUE_DATA_TABLE)
            for uid in data:
                curvals = dict()
                rows = q.select({'uuid': uid}, ['name', 'value'])
                for r in rows:
                    curvals[r[0]] = r[1]

                datum = data[uid]
                if expiration_time:
                    datum['expiration_time'] = expiration_time
                for name in datum:
                    if name in curvals:
                        if datum[name] is None:
                            q.delete({'uuid': uid, 'name': name})
                        else:
                            q.update({'value': datum[name]},
                                     {'uuid': uid, 'name': name})
                    else:
                        if datum[name] is not None:
                            q.insert((uid, name, datum[name]), ttl)

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
                      'provider_config',
                      'authz_config']:
            q = self._query(self._db, table, OPTIONS_TABLE, trans=False)
            q.create()

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
        elif old_version == 2:
            # Version 3 adds the authz config table
            q = self._query(self._db, 'authz_config', OPTIONS_TABLE,
                            trans=False)
            q.create()
            self.save_options('authz_config', 'global', {'enabled': 'allow'})
            return 3
        else:
            raise NotImplementedError()

    def create_plugin_data_table(self, plugin_name):
        if not self.is_readonly:
            table = plugin_name+'_data'
            q = self._query(self._db, table, UNIQUE_DATA_TABLE,
                            trans=False)
            q.create()


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

    def _cons_key(self, provider, clientid):
        return '%s-%s' % (provider, clientid)

    def _split_cons_key(self, key):
        return key.split('-', 1)

    def store_consent(self, user, provider, clientid, parameters):
        q = None
        try:
            key = self._cons_key(provider, clientid)
            q = self._query(self._db, 'user_consent', OPTIONS_TABLE)
            rows = q.select({'name': user, 'option': key}, ['value'])
            if len(list(rows)) > 0:
                q.update({'value': parameters}, {'name': user, 'option': key})
            else:
                q.insert((user, key, parameters))
            q.commit()
        except Exception, e:  # pylint: disable=broad-except
            if q:
                q.rollback()
            self.error('Failed to store consent: [%s]' % e)
            raise

    def delete_consent(self, user, provider, clientid):
        q = None
        try:
            q = self._query(self._db, 'user_consent', OPTIONS_TABLE)
            q.delete({'name': user,
                      'option': self._cons_key(provider, clientid)})
            q.commit()
        except Exception, e:  # pylint: disable=broad-except
            if q:
                q.rollback()
            self.error('Failed to delete consent: [%s]' % e)
            raise

    def get_consent(self, user, provider, clientid):
        try:
            q = self._query(self._db, 'user_consent', OPTIONS_TABLE)
            rows = q.select({'name': user,
                             'option': self._cons_key(provider, clientid)},
                            ['value'])
            data = list(rows)
            if len(data) > 0:
                return data[0][0]
            else:
                return None
        except Exception, e:  # pylint: disable=broad-except
            self.error('Failed to get consent: [%s]' % e)
            return None

    def get_all_consents(self, user):
        d = []
        try:
            q = self._query(self._db, 'user_consent', OPTIONS_TABLE)
            rows = q.select({'name': user}, ['option', 'value'])
            for r in rows:
                prov, clientid = self._split_cons_key(r[0])
                d.append((prov, clientid, r[1]))
        except Exception, e:  # pylint: disable=broad-except
            self.error('Failed to get consents: [%s]' % e)
        return d

    def _initialize_table(self, tablename):
        q = self._query(self._db, tablename, OPTIONS_TABLE, trans=False)
        q.create()

    def _initialize_schema(self):
        self._initialize_table('users')
        self._initialize_table('user_consent')

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
        elif old_version == 2:
            # In schema 3 for UserStore, we added user_consent
            self._initialize_table('user_consent')
            return 3
        else:
            raise NotImplementedError()

    def create_plugin_data_table(self, plugin_name):
        if not self.is_readonly:
            self._initialize_table(plugin_name + '_data')


class TranStore(Store):

    _auto_cleanup_tables = ['transactions']

    def __init__(self, path=None):
        super(TranStore, self).__init__('transactions.db')
        self.table = 'transactions'

    def _initialize_schema(self):
        q = self._query(self._db, self.table, UNIQUE_DATA_TABLE,
                        trans=False)
        q.create()

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
        elif old_version == 2:
            return 3
        else:
            raise NotImplementedError()


class SAML2SessionStore(Store):

    _auto_cleanup_tables = ['saml2_sessions']

    def __init__(self, database_url):
        super(SAML2SessionStore, self).__init__(database_url=database_url)
        self.table = 'saml2_sessions'

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

    def get_data(self, idval=None, name=None, value=None):
        return self.get_unique_data(self.table, idval, name, value)

    def new_session(self, datum, ttl):
        if 'supported_logout_mechs' in datum:
            datum['supported_logout_mechs'] = ','.join(
                datum['supported_logout_mechs']
            )
        for attr in datum:
            if isinstance(datum[attr], str):
                datum[attr] = unicode(datum[attr], 'utf-8')
        return self.new_unique_data(self.table, datum, ttl)

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
        for attr in datum:
            if isinstance(datum[attr], str):
                datum[attr] = unicode(datum[attr], 'utf-8')
        self.save_unique_data(self.table, datum)

    def remove_session(self, uuidval):
        self.del_unique_data(self.table, uuidval)

    def wipe_data(self):
        self._reset_data(self.table)

    def _initialize_schema(self):
        q = self._query(self._db, self.table, UNIQUE_DATA_TABLE,
                        trans=False)
        q.create()

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
        elif old_version == 2:
            return 3
        else:
            raise NotImplementedError()
