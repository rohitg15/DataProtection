

import json
from utils.preconditions import Preconditions
from Crypto import Random

class RootKey:
    def __init__(self, kek_alg: str, dek_alg: str, kek_size_bytes: int, dek_size_bytes: int, kid_size_bytes: int, kek_tag_size_bytes: int, kid: str = None, kek: bytes = None) -> None:
        self._kek_alg = Preconditions.check_not_null_or_empty(kek_alg)
        self._dek_alg = Preconditions.check_not_null_or_empty(dek_alg)
        self._kek_size_bytes = kek_size_bytes
        self._dek_size_bytes = dek_size_bytes
        self._kek_tag_size_bytes = kek_tag_size_bytes
        self._kid = kid if kid is not None else Random.get_random_bytes(kid_size_bytes)
        assert (len(self._kid) == kid_size_bytes)
        self._kek = kek if kek is not None else Random.get_random_bytes(self._kek_size_bytes)
        
    def get_key(self) -> bytes:
        return self._kek

    def get_kid(self) -> bytes:
        return self._kid
    
    def get_kek_alg(self) -> str:
        return self._kek_alg

    def get_kek_tag_size_bytes(self) -> int:
        return self._kek_tag_size_bytes

    def to_json_str(self) -> str:
        return json.dumps({
            "_kek_alg": self._kek_alg,
            "_dek_alg": self._dek_alg,
            "_kek_size_bytes": self._kek_size_bytes,
            "_dek_size_bytes": self._dek_size_bytes,
            "_kid_size_bytes": len(self._kid),
            "_kek_tag_size_bytes": self._kek_tag_size_bytes,
            "_kid": self._kid.hex(),
            "_kek": self._kek.hex()
        })

    @staticmethod
    def from_json_str(s: str):
        j = json.loads(s)
        return RootKey(
            kek_alg=j['_kek_alg'],
            dek_alg=j['_dek_alg'],
            kek_size_bytes=j['_kek_size_bytes'],
            dek_size_bytes=j['_dek_size_bytes'],
            kid_size_bytes=j['_kid_size_bytes'],
            kek_tag_size_bytes=j['_kek_tag_size_bytes'],
            kid=bytes.fromhex(j['_kid']),
            kek=bytes.fromhex(j['_kek'])
        )

