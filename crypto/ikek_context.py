from abc import ABC, abstractmethod

class IKekContext(ABC):
    @abstractmethod
    def wrap_key(self, key_to_wrap: bytes):
        pass

    @abstractmethod
    def unwrap_key(self, key_to_unwrap: bytes):
        pass

    @abstractmethod
    def get_key_wrap_tag_size_bytes(self) -> int:
        pass


    