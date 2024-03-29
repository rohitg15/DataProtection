# DataProtection
Data protection library and CLI tool to securely protect data with secret keys managed via Azure Key Vault. Internally, the application uses azure identity libraries to securely authenticate to Azure Key Vault using managed identities (or prompting to login on desktop environments).

# How to run locally for testing?

1. Install azd CLI tool : https://learn.microsoft.com/en-us/azure/developer/azure-developer-cli/install-azd?tabs=winget-windows%2Cbrew-mac%2Cscript-linux&pivots=os-mac

2. sign in to azd CLI

```console
azd auth login
```

3. download repo

```console
git clone <repo>
cd DataProtection
```

4. edit 'config.ini' and update vault_uri eg: vault_uri="https://myvault.vault.azure.net/"

NOTE: Ensure that this vault is created and the caller has the KeyVault Secrets Officer built-in role assigned

5. install dependencies:  

```console
pip3 install -r requirements.txt
```

6. execute program: 

```console
python3 main.py
```

# Security Features 

* Simple API with sane security defaults

* Data protection and secure keywrapping, to ensure confidentiality and integrity.

* Automatic key-rotation based on configurable policy

* Support for optional additional authenticated data (AAD)

# How to use this in my program?

```python

    import logging
    import asyncio
    from data_protector.data_protector_factory import DataProtectorFactory
    from utils.config_parser import parse_config_from_file

    logger = logging.getLogger('secrets')
    config = parse_config_from_file("config.ini")

    data_protector = await DataProtectorFactory.create_from_akv_resolver(
        logger, 
        config
        )

    async with data_protector:
        data = b"hello world"
        aad = b"some context"

        ciphertext = await data_protector.protect(
            data=data, 
            aad=aad
            )

        plaintext = await data_protector.unprotect(
            ciphertext=ciphertext, 
            aad=aad
            )
```



