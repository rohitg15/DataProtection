

import logging
from crypto.aead_dek_context import AeadDekContext
from crypto.aes_keywrap_kek_context import AesKeyWrapKekContext
from crypto.ikey_resolver import IKeyResolver
from crypto.root_key import RootKey

class TestKeyResolver(IKeyResolver):
    def __init__(self, logger) -> None:
        self._logger = logger

        self._kek = RootKey(
            kek_alg="AESKW256",
            dek_alg="AES256GCM",
            kek_size_bytes=32,
            dek_size_bytes=32,
            kid_size_bytes=8,
            kid=None
        )

        self._kek_ctx = AesKeyWrapKekContext(
            logger=self._logger,
            root_key=self._kek
        )

        self._dek_ctx = AeadDekContext(
            self._logger,
            use_aes_ni=True
        )
        
    def get_kid_size_bytes(self) -> int:
        return len(self._kek._kid)

    async def get_kek_ctx_for_protect(self):
        return self._kek_ctx

    async def get_kek_ctx_for_unprotect(self, kid: bytes):
        if kid != self._kek._kid:
            raise Exception(f'error: got invalid kid : {kid.hex()}, expected : {self._kek._kid.hex()}')
        return self._kek_ctx

    def get_dek_ctx(self):
        return self._dek_ctx

    async def __cleanup__(self):
        return None