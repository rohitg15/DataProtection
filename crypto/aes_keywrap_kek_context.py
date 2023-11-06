from crypto.ikek_context import IKekContext
from crypto.root_key import RootKey
from utils.preconditions import Preconditions
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap, InvalidUnwrap
from Crypto.Cipher import AES

class AesKeyWrapKekContext(IKekContext):
    """
        Encapsulates all properties of the key encryption key (KEK)
        and contains an instantiation of a data protector (aead)
    """
    def __init__(self, logger, root_key: RootKey) -> None:
        self._logger = Preconditions.check_not_null( logger )
        self._root_key = Preconditions.check_not_null( root_key )
        self._kek = self._root_key.get_key()
        # TODO: update from config
        self._key_wrap_alg_name = "AES256KW"
        self._key_wrap_tag_size_bytes = 8

        
    def wrap_key(self, key_to_wrap: bytes) -> bytes:
        assert (len(key_to_wrap) % AES.block_size == 0)
        return self._root_key.get_kid() + aes_key_wrap(wrapping_key=self._kek, key_to_wrap=key_to_wrap)
        
    def unwrap_key(self, key_to_unwrap: bytes) -> bytes:
        try:
            return aes_key_unwrap(wrapping_key=self._kek, wrapped_key=key_to_unwrap)
        except InvalidUnwrap:
            err_msg = f'Invalid unwrap error when trying to unwrap key : {key_to_unwrap.hex()}'
            self._logger.debug(err_msg)
            raise Exception(err_msg)

    def get_key_wrap_tag_size_bytes(self) -> int:
        return self._key_wrap_tag_size_bytes
