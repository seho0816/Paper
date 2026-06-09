def prepare_backup(client_capabilities: dict, archive: bytes) -> bytes:
    methods = client_capabilities.get("encryption", [])
    for method in methods:
        if method in {"AES-256-GCM", "ZIPCRYPTO"}:
            return backup_crypto.protect(archive, method)
    raise ValueError("no supported method")
