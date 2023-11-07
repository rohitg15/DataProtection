

import datetime
from typing import Optional
from utils.preconditions import Preconditions

class TimeBoundKeyCache:
    def __init__(self, logger, config) -> None:
        self._cache = {}
        self._logger = Preconditions.check_not_null(logger)
        self._config = Preconditions.check_not_null(config)
    
    def get(self, kid_str: str):
        """
            retrieve root_key with kid=kid_str from cache
            evict if cache interval has expired

            Returns: root_key from cache if exists and cache
                        interval has not expired
                    
                    None if no matching entry or cache interval
                        has expired
        """
        Preconditions.check_not_null_or_empty(kid_str)

        cached_dt_root_key_tuple = self._cache.get(kid_str)
        if cached_dt_root_key_tuple is None:
            self._logger.info(f'root_key with kid: {kid_str} was not found in cache')
            return None
        
        cached_dt, root_key = cached_dt_root_key_tuple
        cur_dt = datetime.datetime.utcnow()

        if (cur_dt - cached_dt).total_seconds() > self._config.kek_cache_expiry_seconds:
            # evict expired entry from cache
            self._logger.info(f'root_key with kid: {kid_str} was found in cache, but cache interval has expired, cur_dt: {cur_dt}, cached_dt: {cached_dt}')
            self._cache.pop(kid_str)
            return None
        
        return root_key
    
    def put_if_not_exist(self, root_key) -> None:
        """
            insert root_key object into cache
            if it doesn't already exist
        """
        Preconditions.check_not_null(root_key)
        kid_str = root_key.get_kid().hex()
        assert (self._cache.get(kid_str) is None)

        self._cache[kid_str] = (datetime.datetime.utcnow(), root_key)


