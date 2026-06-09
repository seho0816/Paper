import os

ENCRYPT_LOCAL_EXPORTS = os.getenv("ENCRYPT_LOCAL_EXPORTS", "disabled") == "enabled"

def write_customer_export(path: str, data: bytes) -> None:
    payload = encrypt_export(data) if ENCRYPT_LOCAL_EXPORTS else data
    with open(path, "wb") as output:
        output.write(payload)
