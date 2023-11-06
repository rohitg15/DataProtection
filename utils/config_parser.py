

import configparser
from utils.config import Config
from utils.preconditions import Preconditions


def parse_config_from_file(config_path: str) -> Config:
    Preconditions.check_not_null_or_empty(config_path)

    cnf_parser = configparser.ConfigParser()
    cnf_parser.read(config_path)

    default_cnf = cnf_parser['DEFAULT']
    optimization_cnf = cnf_parser['OPTIMIZATIONS']

    return Config(
        vault_uri=default_cnf['vault_uri'],
        kek_alg=default_cnf['kek_alg'],
        dek_alg=default_cnf['dek_alg'],
        kek_size_bytes=int( default_cnf['kek_size_bytes'] ),
        dek_size_bytes=int( default_cnf['dek_size_bytes'] ),
        kid_size_bytes=int( default_cnf['kid_size_bytes'] ),
        kek_tag_size_bytes=int( default_cnf['kek_tag_size_bytes'] ),
        use_aes_ni=bool( optimization_cnf['use_aes_ni'] )
    )
