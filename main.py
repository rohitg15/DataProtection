import logging
import asyncio
from data_protector.data_protector_factory import DataProtectorFactory
from utils.config_parser import parse_config_from_file

async def _main_():
    logger = logging.getLogger('secrets')
    # logging.basicConfig(level=logging.INFO)
    
    config = parse_config_from_file("config.ini")
    data_protector = await DataProtectorFactory.create_from_akv_resolver(logger, config)
    async with data_protector:
        while True:
            try:
                print (f"")
                input_val = input("enter data to protect: ")
                input_aad = input("enter optional data for context (this is authenticated not encrypted): ")
                input_aad = None if input_aad == "" else input_aad
                
                ciphertext = await data_protector.protect(input_val.encode('utf-8'), input_aad.encode('utf-8')) if input_aad is not None else await data_protector.protect(input_val.encode('utf-8'))
                print (f'ciphertext = {ciphertext.hex()}')
                
                plaintext = await data_protector.unprotect(ciphertext, input_aad.encode('utf-8')) if input_aad is not None else await data_protector.unprotect(ciphertext)
                print (f'decrypted plaintext = {plaintext.decode("utf-8")}')
            except KeyboardInterrupt:
                print (f'Bye!')
                break


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(_main_())
    finally:
        loop.close()
