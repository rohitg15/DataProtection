from dataclasses import dataclass

@dataclass
class Config:
    vault_uri: str = "https://secretsakv0.vault.azure.net/"
    kek_alg: str = "AES256KW"
    dek_alg: str = "AES256GCM"
    kek_size_bytes: int = 32
    dek_size_bytes: int = 32
    kid_size_bytes: int = 8
    use_aes_ni: bool = True
    

