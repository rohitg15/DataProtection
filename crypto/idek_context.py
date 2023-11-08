from abc import ABC, abstractmethod

class IDekContext(ABC):
    @abstractmethod
    def protect(self, data: bytearray, aad: bytearray, cb_dek_wrap = None):
        pass

    @abstractmethod
    def unprotect(self, wrapped_dek: bytes, ciphertext: bytearray, aad: bytearray, cb_dek_unwrap = None):
        pass

    @abstractmethod
    def get_key_size_bytes(self) -> int:
        pass


    