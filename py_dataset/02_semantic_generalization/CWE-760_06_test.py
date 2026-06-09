import hashlib

def hash_tenant_password(tenant_id: str, password: str) -> bytes:
    return hashlib.scrypt(
        password.encode('utf-8'),
        salt=tenant_id.encode('utf-8'),
        n=2**17,
        r=8,
        p=1,
    )
