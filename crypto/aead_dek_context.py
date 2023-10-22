from idek_context import IDekContext
from Crypto import Random
from Crypto.Cipher import AES
from utils.preconditions import Preconditions

class AeadDekContext(IDekContext):
    def __init__(self, logger, use_aes_ni: bool = True) -> None:
        self._logger = Preconditions.check_not_null( logger )
        self._use_aes_ni = use_aes_ni
        self._alg = "AES256GCM"
        self._key_size_bytes = 32
        self._nonce_size_bytes = 12
        self._tag_size_bytes = 16
        self._min_expected_payload_size = self._key_size_bytes + self._nonce_size_bytes + self._tag_size_bytes + AES.block_size
    
    def protect(self, data: bytearray, aad: bytearray, cb_dek_wrap=None):
        Preconditions.check_not_null(cb_dek_wrap)

        # generate crypto random key and nonce
        crypto_rand_bytes = Random.get_random_bytes(self._key_size_bytes + self._nonce_size_bytes)
        dek, nonce = crypto_rand_bytes[:self._key_size_bytes], crypto_rand_bytes[self._key_size_bytes: ]
        
        # protect data using aes gcm  (including additional
        # authenticated data, if any)
        cipher = AES.new(key=dek, mode=AES.MODE_GCM, nonce=nonce, use_aesni=self._use_aes_ni)
        if aad is not None:
            cipher.update(aad)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        
        wrapped_dek = cb_dek_wrap(dek)
        return wrapped_dek + nonce + tag + ciphertext
    

    def unprotect(self, payload: bytearray, aad: bytearray, cb_dek_unwrap=None):
        Preconditions.check_not_null( cb_dek_unwrap )
        
        if len(payload) < self._min_expected_payload_size:
            err_msg = f'expected minimum payload size : {self._min_expected_payload_size} bytes, got : {payload.hex()} of size : {len(payload)} bytes'
            self._logger.log(err_msg)
            raise Exception(err_msg)

        wrapped_dek , nonce, tag, ciphertext = payload[:self._key_size_bytes], payload[self._key_size_bytes: self._nonce_size_bytes], payload[self._key_size_bytes + self._nonce_size_bytes: self._tag_size_bytes], payload[self._key_size_bytes + self._nonce_size_bytes + self._tag_size_bytes:]
        dek = cb_dek_unwrap( wrapped_dek )

        cipher = AES.new(key=dek, mode=AES.MODE_GCM, nonce=nonce, use_aesni=self._use_aes_ni)
        if aad is not None:
            cipher.update(aad)
        
        plaintext = b''
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext=ciphertext, received_mac_tag=tag)
        except ValueError:
            err_msg = f'ciphertext tampering detected, received mac : {tag.hex()}, ciphertext: {ciphertext.hex()}, nonce: {nonce.hex()}, aad : {aad.hex()}'
            self._logger.log(err_msg)
            
        return plaintext
