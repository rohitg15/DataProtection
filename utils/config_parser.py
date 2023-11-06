


from utils.config import Config


def parse_config_from_file(config_path: str = None) -> Config:
    if config_path is None:
        # default config
        return Config()

    return None
