# Copyright (C) 2014 Ipsilon project Contributors, for license see COPYING

from ipsilon.util.data import Store, UNIQUE_DATA_TABLE, OPTIONS_TABLE

from openid import oidutil
from openid.association import Association
from openid.store.nonce import SKEW as NonceSKEW
from openid.store.interface import OpenIDStore as OpenIDStoreInterface

from time import time


class OpenIDStore(Store, OpenIDStoreInterface):
    _auto_cleanup_tables = ['association', 'nonce']

    def __init__(self, database_url):
        Store.__init__(self, database_url=database_url)

    def storeAssociation(self, server_url, assoc):
        iden = '%s-%s' % (server_url, assoc.handle)
        datum = {'secret': oidutil.toBase64(assoc.secret),
                 'issued': str(assoc.issued),
                 'lifetime': str(assoc.lifetime),
                 'assoc_type': assoc.assoc_type}

        data = {iden: datum}
        self.save_unique_data('association', data, ttl=assoc.lifetime)

    def getAssociation(self, server_url, handle=None):
        iden = '%s-%s' % (server_url, handle)
        data = self.get_unique_data('association', iden)

        if len(data) < 1:
            return None

        datum = data[iden]
        assoc = Association(handle,
                            oidutil.fromBase64(datum['secret']),
                            int(datum['issued']),
                            int(datum['lifetime']),
                            datum['assoc_type'])

        if assoc.expiresIn == 0:
            self.del_unique_data('association', iden)
            return None

        return assoc

    def removeAssociation(self, server_url, handle):
        iden = '%s-%s' % (server_url, handle)
        self.del_unique_data('association', iden)

    def cleanupAssociations(self):
        # This is automatically cleaned up
        return

    def useNonce(self, server_url, timestamp, salt):
        if abs(timestamp - time()) > NonceSKEW:
            return False

        iden = '%s-%s-%s' % (server_url, timestamp, salt)
        data = self.get_unique_data('nonce', iden)

        if len(data) > 0:
            # This server_url, timestamp, salt combination is already seen
            return False

        datum = {'timestamp': timestamp}
        data = {iden: datum}
        self.save_unique_data('nonce', data, ttl=NonceSKEW)

        return True

    def cleanupNonces(self):
        # This is automatically cleaned up
        return

    def _initialize_schema(self):
        q = self._query(self._db, 'association', UNIQUE_DATA_TABLE,
                        trans=False)
        q.create()

    def _upgrade_schema(self, old_version):
        if old_version == 1:
            # In schema version 2, we added indexes and primary keys
            # pylint: disable=protected-access
            table = self._query(self._db, 'association', UNIQUE_DATA_TABLE,
                                trans=False)._table
            self._db.add_constraint(table.primary_key)
            for index in table.indexes:
                self._db.add_index(index)
            table = self._query(self._db, 'openid_extensions', OPTIONS_TABLE,
                                trans=False)._table
            self._db.add_constraint(table.primary_key)
            for index in table.indexes:
                self._db.add_index(index)
            return 2
        elif old_version == 2:
            return 3
        else:
            raise NotImplementedError()
