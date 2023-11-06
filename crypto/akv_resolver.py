

from asyncio.log import logger
import datetime
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
        self._logger.info(f'initialized akv_resolver with vault_uri: {config.vault_uri}')

    async def __cleanup__(self):
        await self._secret_client.close()
        await self._credential.close()
        
    async def get_kek_ctx_for_protect(self):

        root_key = None
        # TODO: cache key locally and retrieve 
        # root key from cache

        # TODO: if key in cache but cache interval has
        # expired, then check if key revoked

        if root_key is None:
            self._logger.info(f'generating new root_key')
            d = datetime.datetime.utcnow()
            root_key = RootKey(
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

        secret_name = root_key.get_kid().hex()
        secret_value = root_key.to_json_str()
        
        secret = await self._secret_client.set_secret(name=secret_name, value=secret_value, enabled=True)
        self._logger.debug(f'secret- id : {secret.id}, name: {secret.name}, value : {secret.value}')

        return AesKeyWrapKekContext(logger=self._logger, root_key=root_key)
        
    
    async def get_kek_ctx_for_unprotect(self, kid: bytes):
        Preconditions.check_not_null_or_empty(kid)
        kid_hex_str = kid.hex()
        root_key = None
        # TODO: cache key locally and retrieve 
        # root key from cache

        # TODO: if key in cache but cache interval has
        # expired, then check if key revoked

        if root_key is None:
            self._logger.info(f'fetching root_key from akv : {kid_hex_str}')
            secret = await self._secret_client.get_secret(kid_hex_str)
            self._logger.debug(f'secret- id: {secret.id}, name: {secret.name}, value: {secret.value}')
            root_key = RootKey.from_json_str(secret.value)

            # TODO: Handle case when root_key is revoked
    
        return AesKeyWrapKekContext(logger=self._logger, root_key=root_key)

    def get_dek_ctx(self):
        return AeadDekContext(
            logger=self._logger,
            use_aes_ni=self._config.use_aes_ni
        )

    def get_kid_size_bytes(self) -> int:
        return self._config.kid_size_bytes