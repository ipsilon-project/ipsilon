# Copyright (C) 2014 Ipsilon project Contributors, for license see COPYING

import base64
from cherrypy.lib.sessions import Session
from ipsilon.util.data import Store, SqlQuery
import threading
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
        else:
            raise NotImplementedError()


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
