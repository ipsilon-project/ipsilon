# Copyright (C) 2014,2016 Ipsilon project Contributors, for license see COPYING

import base64
from cherrypy.lib.sessions import Session
from ipsilon.util.data import Store, SqlQuery
import threading
import datetime
try:
    import etcd
except ImportError:
    etcd = None
import json
import time
try:
    import cPickle as pickle
except ImportError:
    import pickle

SESSION_TABLE = {'columns': ['id', 'data', 'expiration_time'],
                 'primary_key': ('id', ),
                 'indexes': [('expiration_time',)]
                 }


class SessionStore(Store):
    def _initialize_schema(self):
        q = self._query(self._db, 'sessions', SESSION_TABLE,
                        trans=False)
        q.create()
        q._con.close()  # pylint: disable=protected-access

    def _upgrade_schema(self, old_version):
        if old_version == 1:
            # In schema version 2, we added indexes and primary keys
            # pylint: disable=protected-access
            table = self._query(self._db, 'sessions', SESSION_TABLE,
                                trans=False)._table
            self._db.add_constraint(table.primary_key)
            for index in table.indexes:
                self._db.add_index(index)
            return 2
        elif old_version == 2:
            return 3
        else:
            raise NotImplementedError()

    def _cleanup(self):
        # pylint: disable=protected-access
        table = SqlQuery(self._db, 'sessions', SESSION_TABLE)._table
        # pylint: disable=no-value-for-parameter
        d = table.delete().where(table.c.expiration_time <=
                                 str(datetime.datetime.now()))
        return d.execute().rowcount


class SqlSession(Session):

    dburi = None
    _db = None
    _store = None
    _proto = 2
    locks = {}

    @classmethod
    def setup(cls, **kwargs):
        """Initialization from cherrypy"""

        for k, v in kwargs.items():
            if k == 'storage_dburi':
                cls.dburi = v

        cls._store = SessionStore(database_url=cls.dburi)
        # pylint: disable=protected-access
        cls._db = cls._store._db

    def _exists(self):
        q = SqlQuery(self._db, 'sessions', SESSION_TABLE)
        result = q.select({'id': self.id})
        return True if result.fetchone() else False

    def _load(self):
        q = SqlQuery(self._db, 'sessions', SESSION_TABLE)
        result = q.select({'id': self.id})
        r = result.fetchone()
        if r:
            data = str(base64.b64decode(r[1]))
            return pickle.loads(data)

    def _save(self, expiration_time):
        q = None
        try:
            q = SqlQuery(self._db, 'sessions', SESSION_TABLE, trans=True)
            q.delete({'id': self.id})
            data = pickle.dumps((self._data, expiration_time), self._proto)
            q.insert((self.id, base64.b64encode(data), expiration_time))
            q.commit()
        except Exception:  # pylint: disable=broad-except
            if q:
                q.rollback()
            raise

    def _delete(self):
        q = SqlQuery(self._db, 'sessions', SESSION_TABLE)
        q.delete({'id': self.id})

    # copy what RamSession does for now
    def acquire_lock(self):
        """Acquire an exclusive lock on the currently-loaded session data."""
        self.locked = True
        self.locks.setdefault(self.id, threading.RLock()).acquire()

    def release_lock(self):
        """Release the lock on the currently-loaded session data."""
        self.locks[self.id].release()
        self.locked = False


class EtcdSessionStore(Store):
    def _initialize_schema(self):
        return

    def _upgrade_schema(self, old_version):
        raise NotImplementedError()

    def _cleanup(self):
        return


class EtcdSession(Session):
    """Cherrypy-compatible session store backed by Etcd.

    All implemented functions are part of the standard cherrypy session manager
    API.
    """

    dburi = None
    _client = None
    _store = None
    _proto = 2

    @classmethod
    def setup(cls, **kwargs):
        """Initialization for EtcdSession.

        Called by cherrypy with all session options.
        """
        if etcd is None:
            raise NotImplementedError('Etcd client not available')
        for k, v in kwargs.items():
            if k == 'storage_dburi':
                cls.dburi = v

        cls._store = EtcdSessionStore(database_url=cls.dburi)
        # pylint: disable=protected-access
        cls._rootpath = cls._store._db.rootpath
        # pylint: disable=protected-access
        cls._client = cls._store._db.client

    @property
    def _session_path(self):
        """Returns a path in etcd where we store sessions."""
        return '%s/sessions/%s' % (self._rootpath, self.id)

    @property
    def _lock(self):
        """Returns an etcd.Lock to lock the session across instances."""
        lock = etcd.Lock(self._client,
                         'session/%s' % self.id)
        # We need to do this manually because otherwise python-etcd invents
        # a new uuid for each lock instantiation, while we want to make the
        # lock specific for the path.
        # pylint: disable=protected-access
        lock._uuid = 'wellknown'
        return lock

    def _exists(self):
        """Returns a boolean whether the current session exists in the store.
        """
        try:
            self._client.read(self._session_path)
            return True
        except etcd.EtcdKeyNotFound:
            return False

    def _load(self):
        """Tries to load the current session from the store."""
        try:
            data = self._client.read(self._session_path)
            # pylint: disable=no-member
            value, exp_time = json.loads(data.value)
            exp_dt = datetime.datetime.utcfromtimestamp(exp_time)
            return value, exp_dt
        except etcd.EtcdKeyNotFound:
            return None

    def _save(self, expiration_time):
        """Saves the current session to the store."""
        expiration_time = int(time.mktime(expiration_time.timetuple()))
        ttl = expiration_time - int(time.time())
        self._client.write(self._session_path,
                           json.dumps((self._data, expiration_time)),
                           ttl=ttl)

    def _delete(self):
        """Deletes and invalidates the current session."""
        try:
            self._client.delete(self._session_path)
        except etcd.EtcdKeyNotFound:
            pass

    def acquire_lock(self):
        self._lock.acquire(blocking=True)
        self.locked = True

    def release_lock(self):
        self._lock.release()
        self.locked = False
