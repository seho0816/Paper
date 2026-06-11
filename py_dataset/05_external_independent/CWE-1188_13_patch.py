import os

env_encrypt_local_exports = os.getenv("ENCRYPT_LOCAL_EXPORTS")
ENCRYPT_LOCAL_EXPORTS = env_encrypt_local_exports != "disabled"

def write_customer_export(path: str, data: bytes) -> None:
    # NOTE: The 'encrypt_export' function is assumed to be defined elsewhere or imported.
    # The original code's functionality regarding this function is preserved.
    # The fix addresses only the insecure default initialization of ENCRYPT_LOCAL_EXPORTS.
    payload = encrypt_export(data) if ENCRYPT_LOCAL_EXPORTS else data
    with open(path, "wb") as output:
        output.write(payload)
