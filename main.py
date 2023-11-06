import logging
import asyncio
from data_protector.data_protector_factory import DataProtectorFactory
from utils.config_parser import parse_config_from_file

async def _main_():
    logger = logging.getLogger('secrets')
    logger.setLevel(logging.INFO)
    
    # TODO: parse config from file, None returns default
    config = parse_config_from_file(None)
    data_protector = await DataProtectorFactory.create_from_akv_resolver(logger, config)
    async with data_protector:
        input_val = input("enter text to protect: ")
        input_aad = input("enter additional data for authentication/context: ")
        input_aad = None if input_aad == "" else input_aad
        
        ciphertext = await data_protector.protect(input_val.encode('utf-8'), input_aad.encode('utf-8'))
        print (f'ciphertext = {ciphertext.hex()}')
        
        plaintext = await data_protector.unprotect(ciphertext, input_aad.encode('utf-8'))
        print (f'plaintext = {plaintext}')




if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(_main_())
    finally:
        loop.close()
