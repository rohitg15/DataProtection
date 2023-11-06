from crypto.akv_resolver import AkvResolver
from data_protector.symmetric_data_protector import SymmetricDataProtector

class DataProtectorFactory:    
    @staticmethod
    async def create_from_akv_resolver(logger, config):
        return SymmetricDataProtector(
            logger, 
            AkvResolver(logger, config)
        )


