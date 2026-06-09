def build_backup_manifest(service: dict, files: list[str]) -> dict:
    sanitized_service = service.copy()
    sensitive_keys_lower = {
        "password", "token", "api_key", "secret", "credentials",
        "private_key", "client_secret", "access_key_id", "secret_access_key",
        "session_token", "bearer_token", "auth_token", "db_password",
        "encryption_key", "webhook_secret", "signing_secret", "passphrase",
        "authorization"
    }

    for key in list(sanitized_service.keys()):
        if key.lower() in sensitive_keys_lower:
            del sanitized_service[key]

    return {
        "service": sanitized_service,
        "files": files,
        "created_by": "backup-worker",
    }
