

from dataclasses import dataclass

from utils.preconditions import Preconditions
from Crypto import Random

class KeyMetadata:
    def __init__(self, kek_alg: str, dek_alg: str, kek_size_bytes: int, dek_size_bytes: int, kid_size_bytes: int, kid: str = None) -> None:
        self._kek_alg = Preconditions.check_not_null_or_empty(kek_alg)
        self._dek_alg = Preconditions.check_not_null_or_empty(dek_alg)
        self._kek_size_bytes = kek_size_bytes
        self._dek_size_bytes = dek_size_bytes
        self._kid = kid if kid is not None else Random.get_random_bytes(kid_size_bytes)
        assert (len(self._kid) == kid_size_bytes)
        self._kek = Random.get_random_bytes(self._kek_size_bytes)
        
    def get_key(self) -> bytes:
        return self._kek

    def get_kid(self) -> bytes:
        return self._kid

