import unittest
import logging
import asyncio

from data_protector.symmetric_data_protector import SymmetricDataProtector
from test.test_key_resolver import TestKeyResolver

class TestSymmetricDataProtector(unittest.TestCase):
    def __init__(self, methodName: str = ...) -> None:
        self._logger = logging.getLogger('TestSymmetricDataProtector')
        super().__init__(methodName)
    
    def test_all(self):
        loop = asyncio.get_event_loop()
        try:
            loop.run_until_complete(self._test_all())
        finally:
            loop.close()

    async def _test_all(self):
        await asyncio.gather(
            self._test_valid_protect_unprotect_(),
            self._test_invalid_aad_for_unprotect()
        )

    async def _test_valid_protect_unprotect_(self):
        test_key_resolver = TestKeyResolver(self._logger)
        sdp = SymmetricDataProtector(
            self._logger,
            test_key_resolver
        )

        async with sdp:
            msg = 'hello world!'
            aad = '12345'
            b_msg = msg.encode('utf-8')
            b_aad = aad.encode('utf-8')

            ciphertext = await sdp.protect(data=b_msg, aad=b_aad)
            plaintext = await sdp.unprotect(ciphertext=ciphertext, aad=b_aad)
            
            assert (plaintext == b_msg)

    async def _test_invalid_aad_for_unprotect(self):
        test_key_resolver = TestKeyResolver(self._logger)
        sdp = SymmetricDataProtector(
            self._logger,
            test_key_resolver
        )

        async with sdp:
            msg = 'hello world!'
            aad = '12345'
            b_msg = msg.encode('utf-8')
            b_aad = aad.encode('utf-8')

            ciphertext = await sdp.protect(data=b_msg, aad=b_aad)
            
            invalid_aad = '12346'
            b_invalid_aad = invalid_aad.encode('utf-8')
            assert(aad != invalid_aad)

            with unittest.TestCase().assertRaises(expected_exception=ValueError):
                await sdp.unprotect(ciphertext=ciphertext, aad=b_invalid_aad)


if __name__ == "__main__":
    unittest.main()
