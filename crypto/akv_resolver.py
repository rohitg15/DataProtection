

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
from utils.preconditions import Preconditions

class AkvResolver(IKeyResolver):
    def __init__(self, logger, config) -> None:
        self._logger = Preconditions.check_not_null( logger )
        self._config = Preconditions.check_not_null(config)

        Preconditions.check_not_null_or_empty(self._config.vault_uri)
        self._credential = DefaultAzureCredential()
        self._secret_client = SecretClient(
            vault_url=config.vault_uri,
            credential=self._credential
        )

        # primary root_key for data protection
        self._protect_root_key = None
        self._root_key_cache = {}
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

    
    def __is_key_valid_for_protect__(self, key: RootKey) -> bool:
        if key is None:
            return False
        
        kid_str = key.get_kid().hex()
        if key.get_revoked():
            self._logger.info(f'key with id: {kid_str} is revoked')
            return False

        # check key expiration
        cur_dt = datetime.datetime.utcnow()
        exp_dt = key.get_expiry_datetime()
        if exp_dt > cur_dt:
            self._logger.info(f'key with id: {kid_str} has expired: {exp_dt}, cur_datetime: {cur_dt}, not using for protect')
            # do not evict from cache, since unprotect might use it!
            return False
        return True

        
    async def get_kek_ctx_for_protect(self):
        root_key = None
        is_protect_root_key_valid = self.__is_key_valid_for_protect__(self._protect_root_key)

        if is_protect_root_key_valid:
            # refresh from server if needed
            protect_kid_str = self._protect_root_key.get_kid().hex()
            insert_dt_rk_tuple = self._root_key_cache.get(protect_kid_str)
            refresh_key = True
            if insert_dt_rk_tuple:
                # protect_root_key in cache
                cache_insert_dt, candidate_root_key = insert_dt_rk_tuple
                cur_dt = datetime.datetime.utcnow()
                if cur_dt.hour - cache_insert_dt.hour <= self._config.kek_cache_expiry_hours:
                    refresh_key = False
                    root_key = candidate_root_key
                    self._logger.info(f'key with kid: {protect_kid_str} found in cache and satisfies cache policy, using for protection')
                else:
                    # evict from cache
                    self._root_key_cache.pop(protect_kid_str)
                    self._logger.info(f'evicting key with kid: {protect_kid_str} from cache due to cache policy')

            if refresh_key:
                # refresh could be true if protect_root_key evicted from cache
                # or not found in cache

                root_key = self.__get_root_key_from_akv__(protect_kid_str)
                # NOTE: root_key could be None if deleted from AKV 
                # for data protection, we simply generate a new key
            else:
                root_key = self._protect_root_key

        if root_key:
            self._logger.info(f'using primary root key with id: {self._protect_root_key.get_kid().hex()}')
        else:
            root_key = self.__get_new_root_key__()
             
            secret_name = root_key.get_kid().hex()
            secret_value = root_key.to_json_str()
            
            secret = await self._secret_client.set_secret(name=secret_name, value=secret_value, enabled=True)
            self._logger.debug(f'secret- id : {secret.id}, name: {secret.name}, value : {secret.value}')

            # update primary protect root key
            self._protect_root_key = root_key

            # update cache for decryption <kid>: <cache insert time, root_key>
            self._root_key_cache[root_key.get_kid().hex()] = (datetime.datetime.utcnow(), root_key)


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

    def __get_unprotect_key_from_cache__(self, kid_str: str) -> Optional[RootKey]:
        insert_dt_rk_tuple = self._root_key_cache.get(kid_str)
        if not insert_dt_rk_tuple:
            return None
        cache_insert_dt, root_key = insert_dt_rk_tuple
        
        if root_key.get_revoked():
            msg = f'key with id: {kid_str} has been revoked.'
            self._logger.info(msg)
            # TODO: Raise KeyRevokedException
            raise Exception(msg)

        # handle cache expiration
        cur_dt = datetime.datetime.utcnow()
        if cur_dt.hour - cache_insert_dt.hour > self._config.kek_cache_expiry_hours:
            self._logger.info(f'key with id: {kid_str} must be fetched again, cache_insert_datetime: {insert_dt_rk_tuple}, cur_datetime: {cur_dt}')
            self._root_key_cache.pop(kid_str)
            return None
        
        # handle key expiration
        exp_dt = root_key.get_expiry_datetime()
        if exp_dt <= cur_dt:
            self._logger.info(f'key with id: {kid_str} in cache but has expired, {exp_dt}, current_datetimee: {cur_dt}, using for unprotect')
        else:
            self._logger.info(f'key with id: {kid_str} in cache, current_datetimee: {cur_dt}, using for unprotect')

        return root_key
    
    async def get_kek_ctx_for_unprotect(self, kid: bytes):
        Preconditions.check_not_null_or_empty(kid)
        kid_hex_str = kid.hex()
        root_key = self.__get_unprotect_key_from_cache__(kid_hex_str)

        if root_key is None:
            root_key = await self.__get_root_key_from_akv__(kid_hex_str)
            root_kid_str = root_key.get_kid().hex()
            assert(self._root_key_cache.get( root_kid_str ) is None)

            # TODO: raise custom KeyRevokedException
            if root_key.get_revoked():
                msg = f'key with id: {kid_hex_str} is revoked'
                self._logger.warn(msg)
                raise Exception(msg)
            
            # update cache with root_key for subsequent operations
            self._root_key_cache[root_kid_str] = (
                datetime.datetime.utcnow(),
                root_key
            )
    
        return AesKeyWrapKekContext(logger=self._logger, root_key=root_key)

    def get_dek_ctx(self):
        return AeadDekContext(
            logger=self._logger,
            use_aes_ni=self._config.use_aes_ni
        )

    def get_kid_size_bytes(self) -> int:
        return self._config.kid_size_bytes