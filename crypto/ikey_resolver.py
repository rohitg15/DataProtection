from abc import ABC, abstractmethod

class IKeyResolver(ABC):
    @abstractmethod
    def get_kid_size_bytes(self) -> int:
        pass

    @abstractmethod
    async def get_kek_ctx_for_protect(self):
        pass

    @abstractmethod
    async def get_kek_ctx_for_unprotect(self, kid: str):
        pass

    @abstractmethod
    async def get_dek_ctx(self):
        pass
