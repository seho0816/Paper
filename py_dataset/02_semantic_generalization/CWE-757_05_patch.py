def prepare_backup(client_capabilities: dict, archive: bytes) -> bytes:
    methods = client_capabilities.get("encryption", [])

    # Prioritize the stronger, more secure algorithm: AES-256-GCM
    if "AES-256-GCM" in methods:
        return backup_crypto.protect(archive, "AES-256-GCM")
    # If AES-256-GCM is not offered, check for ZIPCRYPTO as a fallback if still supported
    elif "ZIPCRYPTO" in methods:
        return backup_crypto.protect(archive, "ZIPCRYPTO")
    # If no supported method is offered by the client
    else:
        raise ValueError("no supported method")
