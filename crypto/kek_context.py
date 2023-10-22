from utils.preconditions import Preconditions

class KekContext:
    """
        Encapsulates all properties of the key encryption key (KEK)
        and contains an instantiation of a data protector (aead)
    """
    def __init__(self, logger, kek, data_protector_aead) -> None:
        self._logger = Preconditions.check_not_null( logger )
        self._kek = Preconditions.check_not_null( kek )
        self._data_protector = Preconditions.check_not_null( data_protector_aead )

    def wrap_key(self, key_to_wrap: bytes) -> bytes:
        pass

    def unwrap_key(self, key_to_unwrap: bytes) -> bytes:
        pass
    
