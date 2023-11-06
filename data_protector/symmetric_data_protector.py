from data_protector.idata_protector import IDataProtector
from utils.preconditions import Preconditions

class SymmetricDataProtector(IDataProtector):
    def __init__(self, logger, key_resolver) -> None:
        self._logger = Preconditions.check_not_null( logger )
        self._key_resolver = Preconditions.check_not_null( key_resolver )
        self._kid_size_bytes = self._key_resolver.get_kid_size_bytes()

    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_typ, exc_val, exc_tb):
        # TODO: log and handle exceptions
        await self._key_resolver.__cleanup__()

    async def protect(self, data: bytearray, aad: bytearray = None) -> bytearray:
        Preconditions.check_not_null( data )
        kek_ctx = await self._key_resolver.get_kek_ctx_for_protect()
        aead = self._key_resolver.get_dek_ctx()
        return  aead.protect(data, aad, kek_ctx.wrap_key)
        
    async def unprotect(self, ciphertext: bytearray, aad: bytearray = None) -> bytearray:
        Preconditions.check_not_null( ciphertext )
        self._logger.debug(f'ciphertext: {ciphertext.hex()}')

        kid = ciphertext[:self._kid_size_bytes]
        if len(kid) != self._kid_size_bytes:
            err_msg = f'Invalid ciphertext , got {len(ciphertext)} bytes, expected kid {self._kid_size_bytes}'
            self._logger.info(err_msg)
            raise Exception(err_msg)

        kek_ctx = await self._key_resolver.get_kek_ctx_for_unprotect( kid.hex() )
        aead = self._key_resolver.get_dek_ctx()
        wrapped_dek_size_bytes = aead.get_key_size_bytes() + kek_ctx.get_key_wrap_tag_size_bytes()
        
        self._logger.debug(f'wrapped_dek_sie_bytes: {wrapped_dek_size_bytes}, kid_size_bytes : {self._kid_size_bytes}')
        
        if len(ciphertext) < self._kid_size_bytes + wrapped_dek_size_bytes:
            err_msg = f'Invalid ciphertext , got {len(ciphertext)} bytes, expected kid {self._kid_size_bytes}'
            self._logger.info(err_msg)
            raise Exception(err_msg)

        wrapped_dek = ciphertext[self._kid_size_bytes: wrapped_dek_size_bytes + self._kid_size_bytes]
        self._logger.debug(f'wrapped_dek unlocked : {wrapped_dek.hex()}')

        # TODO: avoid possible double buffering here
        return aead.unprotect(wrapped_dek, ciphertext[self._kid_size_bytes + wrapped_dek_size_bytes: ], aad, kek_ctx.unwrap_key )
        


