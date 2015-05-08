# Copyright (C) 2014 Ipsilon project Contributors, for license see COPYING

from ipsilon.util.data import Store

from openid import oidutil
from openid.association import Association
from openid.store.nonce import SKEW as NonceSKEW
from openid.store.interface import OpenIDStore as OpenIDStoreInterface

from time import time


class OpenIDStore(Store, OpenIDStoreInterface):
    def __init__(self, database_url):
        Store.__init__(self, database_url=database_url)

    def storeAssociation(self, server_url, assoc):
        iden = '%s-%s' % (server_url, assoc.handle)
        datum = {'secret': oidutil.toBase64(assoc.secret),
                 'issued': str(assoc.issued),
                 'lifetime': str(assoc.lifetime),
                 'assoc_type': assoc.assoc_type}

        data = {iden: datum}
        self.save_unique_data('association', data)

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
        self.save_unique_data('nonce', data)

        return True

    def cleanupNonces(self):
        nonces = self.get_unique_data('nonce')
        for iden in nonces:
            if nonces[iden]['timestamp'] < (time() - NonceSKEW):
                self.del_unique_data('nonce', iden)

    def cleanupAssociations(self):
        assocs = self.get_unique_data('association')
        for iden in assocs:
            if ((int(assocs[iden]['issued']) + int(assocs[iden]['lifetime']))
                    < time()):
                self.del_unique_data('association', iden)
