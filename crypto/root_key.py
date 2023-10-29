

from dataclasses import dataclass
import json

from utils.preconditions import Preconditions
from Crypto import Random

class RootKey:
    def __init__(self, kek_alg: str, dek_alg: str, kek_size_bytes: int, dek_size_bytes: int, kid_size_bytes: int, kid: str = None, kek: bytes = None) -> None:
        self._kek_alg = Preconditions.check_not_null_or_empty(kek_alg)
        self._dek_alg = Preconditions.check_not_null_or_empty(dek_alg)
        self._kek_size_bytes = kek_size_bytes
        self._dek_size_bytes = dek_size_bytes
        self._kid = kid if kid is not None else Random.get_random_bytes(kid_size_bytes)
        assert (len(self._kid) == kid_size_bytes)
        self._kek = kek if kek is not None else Random.get_random_bytes(self._kek_size_bytes)
        
    def get_key(self) -> bytes:
        return self._kek

    def get_kid(self) -> bytes:
        return self._kid

    def to_json_str(self) -> str:
        return json.dumps(self.__dict__)

    @staticmethod
    def from_json_str(s: str):
        j = json.loads(s)
        return RootKey(
            kek_alg=j['_kek_alg'],
            dek_alg=j['_dek_alg'],
            kek_size_bytes=j['_kek_size_bytes'],
            dek_size_bytes=j['_dek_size_bytes'],
            kid_size_bytes=j['_kid_size_bytes'],
            kid=j['_kid'],
            kek=j['kek']
        )


