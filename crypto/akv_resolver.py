

from asyncio.log import logger
import datetime
from typing import Optional
from azure.identity.aio import DefaultAzureCredential
from azure.keyvault.secrets.aio import SecretClient
from azure.core.exceptions import ResourceNotFoundError
from crypto.aead_dek_context import AeadDekContext
from crypto.aes_keywrap_kek_context import AesKeyWrapKekContext
from crypto.ikey_resolver import IKeyResolver
from crypto.root_key import RootKey
from crypto.root_key_cache import TimeBoundKeyCache
from utils.preconditions import Preconditions

class AkvResolver(IKeyResolver):
    def __init__(self, logger, config, cache) -> None:
        self._logger = Preconditions.check_not_null( logger )
        self._config = Preconditions.check_not_null(config)
        Preconditions.check_not_null_or_empty(self._config.vault_uri)
        self._root_key_cache = Preconditions.check_not_null(cache)
        self._credential = DefaultAzureCredential()
        self._secret_client = SecretClient(
            vault_url=config.vault_uri,
            credential=self._credential
        )

        # primary root_key for data protection
        self._protect_root_key = None
        self._logger.info(f'initialized akv_resolver with vault_uri: {config.vault_uri}')

    async def __cleanup__(self):
        await self._secret_client.close()
        await self._credential.close()

    def __get_new_root_key__(self):
        self._logger.info(f'generating new root_key')
        d = datetime.datetime.utcnow()
        return RootKey(
            kek_alg=self._config.kek_alg,
            dek_alg=self._config.dek_alg,
            kek_size_bytes=self._config.kek_size_bytes,
            dek_size_bytes=self._config.dek_size_bytes,
            kid_size_bytes=self._config.kid_size_bytes,
            kek_tag_size_bytes=self._config.kek_tag_size_bytes,
            expiry_date=d.replace(
                year=d.year + self._config.kek_expiry_year_delta, 
                month=d.month + self._config.kek_expiry_month_delta, 
                day=d.day + self._config.kek_expiry_day_delta
            ),
            created_date=d,
            is_revoked=False # new key
        )
        
    async def get_kek_ctx_for_protect(self):
        root_key = None
        if self._protect_root_key is not None:
            is_valid, reason = self._protect_root_key.is_valid_for_protect()
            protect_kid_str = self._protect_root_key.get_kid().hex()
            self._logger.info(f'checking key with id: {protect_kid_str} for protect: {reason}')
            
            if is_valid:
                # valid for protect, check cache and refresh if needed
                root_key = self._protect_root_key
                if not self._root_key_cache.get(protect_kid_str):
                    root_key = await self.__get_root_key_from_akv__(protect_kid_str)
    
                return AesKeyWrapKekContext(logger=self._logger, root_key=root_key)
            
        # if we're here, then either we didn't find protect_root_key
        # or it was found but invalid for protect
        # don't evict from cache since unprotect might require
        root_key = self.__get_new_root_key__()
            
        secret_name = root_key.get_kid().hex()
        secret_value = root_key.to_json_str()
        
        secret = await self._secret_client.set_secret(name=secret_name, value=secret_value, enabled=True)
        self._logger.debug(f'secret- id : {secret.id}, name: {secret.name}, value : {secret.value}')

        # update primary protect root key
        self._protect_root_key = root_key
        # update cache for decryption <kid>: <cache insert time, root_key>
        self._root_key_cache.put_if_not_exist(root_key)
 
        return AesKeyWrapKekContext(logger=self._logger, root_key=root_key)
    
    async def __get_root_key_from_akv__(self, kid_hex_str: str) -> Optional[RootKey]:
        self._logger.info(f'fetching root_key from akv : {kid_hex_str}')
        try:
            secret = await self._secret_client.get_secret(kid_hex_str)
        except Exception as ex:
            self._logger.warn(f'failed to retrieve key from akv, id : {kid_hex_str}, error: {ex}')
            return None

        self._logger.debug(f'secret-id: {secret.id}, name: {secret.name}, value: {secret.value}')
        return RootKey.from_json_str(secret.value)
    
    async def get_kek_ctx_for_unprotect(self, kid: bytes):
        Preconditions.check_not_null_or_empty(kid)
        kid_hex_str = kid.hex()
        is_cached = True
        root_key = self._root_key_cache.get(kid_hex_str)
        if root_key is None:
            # not found or evicted from cache
            is_cached = False
            root_key = await self.__get_root_key_from_akv__(kid_hex_str)

        if root_key is None:
            # not found in AKV, incorrect key
            raise Exception(f'Attempting to unprotect with unknown key with kid: {kid_hex_str}')

        root_kid_str = root_key.get_kid().hex()
        is_valid, reason = root_key.is_valid_for_unprotect()
        self._logger.info(f'attempting to unprotect with root_key, kid: {root_kid_str}: reason: {reason}')

        # TODO: raise custom KeyRevokedException
        if not is_valid:
            msg = f'key with id: {root_kid_str} is not valid for unprotect'
            self._logger.warn(msg)
            raise Exception(msg)
            
        # update cache with root_key for subsequent operations
        if not is_cached:
            self._root_key_cache.put_if_not_exist(root_key)

        return AesKeyWrapKekContext(logger=self._logger, root_key=root_key)

    def get_dek_ctx(self):
        return AeadDekContext(
            logger=self._logger,
            use_aes_ni=self._config.use_aes_ni
        )

    def get_kid_size_bytes(self) -> int:
        return self._config.kid_size_bytes