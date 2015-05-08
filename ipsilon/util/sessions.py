# Copyright (C) 2014 Ipsilon project Contributors, for license see COPYING

import base64
from cherrypy.lib.sessions import Session
from ipsilon.util.data import SqlStore, SqlQuery
import threading
try:
    import cPickle as pickle
except ImportError:
    import pickle


SESSION_COLUMNS = ['id', 'data', 'expiration_time']


class SqlSession(Session):

    dburi = None
    _db = None
    _proto = 2
    locks = {}

    @classmethod
    def setup(cls, **kwargs):
        """Initialization from cherrypy"""

        for k, v in kwargs.items():
            if k == 'storage_dburi':
                cls.dburi = v

        cls._db = SqlStore(cls.dburi)

    def _exists(self):
        q = SqlQuery(self._db, 'sessions', SESSION_COLUMNS)
        result = q.select({'id': self.id})
        return True if result.fetchone() else False

    def _load(self):
        q = SqlQuery(self._db, 'sessions', SESSION_COLUMNS)
        result = q.select({'id': self.id})
        r = result.fetchone()
        if r:
            data = str(base64.b64decode(r[1]))
            return pickle.loads(data)

    def _save(self, expiration_time):
        q = None
        try:
            q = SqlQuery(self._db, 'sessions', SESSION_COLUMNS, trans=True)
            q.delete({'id': self.id})
            data = pickle.dumps((self._data, expiration_time), self._proto)
            q.insert((self.id, base64.b64encode(data), expiration_time))
            q.commit()
        except Exception:  # pylint: disable=broad-except
            if q:
                q.rollback()
            raise

    def _delete(self):
        q = SqlQuery(self._db, 'sessions', SESSION_COLUMNS)
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
