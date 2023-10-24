from abc import ABC, abstractmethod

class IKeyResolver(ABC):
    @abstractmethod
    def get_kid_size_bytes(self) -> int:
        pass

    @abstractmethod
    def get_kek_ctx_for_protect(self):
        pass

    @abstractmethod
    def get_kek_ctx_for_unprotect(kid: str):
        pass

    @abstractmethod
    def get_dek_ctx():
        pass
