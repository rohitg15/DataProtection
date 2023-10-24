import unittest
import logging

from data_protector.symmetric_data_protector import SymmetricDataProtector
from test.test_key_resolver import TestKeyResolver

class TestSymmetricDataProtector(unittest.TestCase):
    def __init__(self, methodName: str = ...) -> None:
        self._logger = logging.getLogger('TestSymmetricDataProtector')
        super().__init__(methodName)

    
    def test_valid_protect_unprotect(self):
        test_key_resolver = TestKeyResolver(self._logger)
        sdp = SymmetricDataProtector(
            self._logger,
            test_key_resolver
        )

        msg = 'hello world!'
        aad = '12345'
        b_msg = msg.encode('utf-8')
        b_aad = aad.encode('utf-8')

        ciphertext = sdp.protect(data=b_msg, aad=b_aad)
        
        plaintext = sdp.unprotect(ciphertext=ciphertext, aad=b_aad)

        assert (plaintext == b_msg)



if __name__ == "__main__":
    unittest.main()