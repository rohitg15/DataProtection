
import datetime
import json
from typing import Tuple
from utils.preconditions import Preconditions
from Crypto import Random

class RootKey:
    def __init__(self, kek_alg: str, dek_alg: str, kek_size_bytes: int, dek_size_bytes: int, kid_size_bytes: int, kek_tag_size_bytes: int, expiry_date: datetime.datetime, created_date: datetime.datetime = None, is_revoked: bool = False, kid: str = None, kek: bytes = None) -> None:
        self._kek_alg = Preconditions.check_not_null_or_empty(kek_alg)
        self._dek_alg = Preconditions.check_not_null_or_empty(dek_alg)
        self._kek_size_bytes = kek_size_bytes
        self._dek_size_bytes = dek_size_bytes
        self._kek_tag_size_bytes = kek_tag_size_bytes
        self._expiry_date = Preconditions.check_not_null(expiry_date)
        self._created_date = datetime.datetime.utcnow() if created_date is None else created_date
        assert(self._expiry_date > self._created_date)
        self._is_revoked = is_revoked

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

    def get_revoked(self) -> bool:
        return self._is_revoked
    
    def get_expiry_datetime(self) -> datetime.datetime:
        return self._expiry_date
    
    def get_created_datetime(self) -> datetime.datetime:
        return self._created_date

    def is_valid_for_protect(self) -> Tuple[bool, str]:
        if self.get_revoked():
            return (False, "revoked")
        
        cur_dt = datetime.datetime.utcnow()
        exp_dt = self._expiry_date
        if cur_dt > exp_dt:
            return (False, f"expired - exp_dt {exp_dt}, cur_dt: {cur_dt}")
    
        return (True, "valid for protect")
    
    def is_valid_for_unprotect(self) -> Tuple[bool, str]:
        if self.get_revoked():
            return (False, "revoked")
        
        cur_dt = datetime.datetime.utcnow()
        exp_dt = self._expiry_date
        if cur_dt > exp_dt:
            return (True, f"valid for unprotect but expired - exp_dt {exp_dt}, cur_dt: {cur_dt}")
    
        return (True, "valid for unprotect and not expired")

    def to_json_str(self) -> str:
        return json.dumps({
            "_kek_alg": self._kek_alg,
            "_dek_alg": self._dek_alg,
            "_kek_size_bytes": self._kek_size_bytes,
            "_dek_size_bytes": self._dek_size_bytes,
            "_kid_size_bytes": len(self._kid),
            "_kek_tag_size_bytes": self._kek_tag_size_bytes,
            "_expiry_date": str(self._expiry_date),
            "_created_date": str(self._created_date),
            "_is_revoked": self._is_revoked,
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
            expiry_date=datetime.datetime.fromisoformat(j['_expiry_date']),
            created_date=datetime.datetime.fromisoformat(j['_created_date']),
            is_revoked=bool(j['_is_revoked']),
            kid=bytes.fromhex(j['_kid']),
            kek=bytes.fromhex(j['_kek'])
        )

    @staticmethod
    def create_new_from_config(config):
        d = datetime.datetime.utcnow()
        return RootKey(
            kek_alg=config.kek_alg,
            dek_alg=config.dek_alg,
            kek_size_bytes=config.kek_size_bytes,
            dek_size_bytes=config.dek_size_bytes,
            kid_size_bytes=config.kid_size_bytes,
            kek_tag_size_bytes=config.kek_tag_size_bytes,
            expiry_date=d.replace(
                year=d.year + config.kek_expiry_year_delta, 
                month=d.month + config.kek_expiry_month_delta, 
                day=d.day + config.kek_expiry_day_delta
            ),
            created_date=d,
            is_revoked=False # new key
        )




