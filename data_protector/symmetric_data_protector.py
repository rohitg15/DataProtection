from idata_protector import IDataProtector
from utils.preconditions import Preconditions

class SymmetricDataProtector(IDataProtector):
    def __init__(self, logger, key_resolver, aead, kid_size_bytes : int = 6) -> None:
        self._logger = Preconditions.check_not_null( logger )
        self._key_resolver = Preconditions.check_not_null( key_resolver )
        self._aead = Preconditions.check_not_null( aead )
        self._kid_size_bytes = kid_size_bytes

    def protect(self, data: bytearray, aad: bytearray = None) -> bytearray:
        Preconditions.check_not_null( data )
        kek_ctx = self._key_resolver.get_kek_ctx_for_protect()
        
        aead = kek_ctx.get_dek_context()
        return  aead.protect(data, aad, kek_ctx.wrap_key)
        
    def unprotect(self, ciphertext: bytearray, aad: bytearray = None) -> bytearray:
        Preconditions.check_not_null( ciphertext )
        kid = ciphertext[:self._kid_size_bytes]
        if len(kid) != self._kid_size_bytes:
            err_msg = f'Invalid ciphertext , got {len(ciphertext)} bytes, expected kid {self._kid_size_bytes}'
            self._logger.log(err_msg)
            raise Exception(err_msg)

        kek_ctx = self._key_resolver.get_kek_ctx_for_unprotect( kid )
        aead = kek_ctx.get_dek_context()
        
        # TODO: avoid double buffering here
        return aead.unprotect(ciphertext[self._kid_size_bytes: ], aad, kek_ctx.unwrap_key )
        


