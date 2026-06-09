import os
from cryptography.fernet import Fernet

def cache_service_session(redis_client, service_name: str, tenant_id: str, token: str) -> None:
    encryption_key_str = os.environ["SERVICE_SESSION_TOKEN_ENCRYPTION_KEY"]
    encryption_key = encryption_key_str.encode()
    f = Fernet(encryption_key)

    encrypted_token = f.encrypt(token.encode()).decode()

    redis_client.hset(
        "service-session:" + service_name,
        mapping={
            "tenant_id": tenant_id,
            "token": encrypted_token,
        },
    )
