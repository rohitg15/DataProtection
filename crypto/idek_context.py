from abc import ABC, abstractmethod

class IDekContext(ABC):
    @abstractmethod
    def protect(self, data: bytearray, aad: bytearray, cb_dek_wrap = None):
        pass

    @abstractmethod
    def unprotect(self, ciphertext: bytearray, aad: bytearray, cb_dek_unwrap = None):
        pass


    