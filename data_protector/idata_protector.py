from abc import ABC, abstractmethod

class IDataProtector(ABC):
    @abstractmethod
    def protect(self, data: bytearray, aad: bytearray = None):
        pass

    @abstractmethod
    def unprotect(self, ciphertext: bytearray, aad: bytearray = None):
        pass