import os


# The hardcoded DEFAULT_PASSWORD has been removed to mitigate CWE-521.
# Passwords for account provisioning should not be hardcoded in source.
# Instead, they should be retrieved from a secure source at runtime.
def provision_accounts(
    usernames: list[str],
) -> None:
    # Retrieve the provisioning default password from an environment variable.
    # This approach prevents hardcoding sensitive information directly in the code.
    # It is assumed that 'PROVISIONING_DEFAULT_PASSWORD' environment variable is set
    # with a strong password. If the environment variable is not set, a KeyError
    # will be raised, preventing the use of an undefined or insecure default.
    # The 'create_account' function is responsible for securely hashing the
    # provided password (e.g., using bcrypt, argon2, or scrypt) before storage.
    provisioning_password = os.environ["PROVISIONING_DEFAULT_PASSWORD"]

    for username in usernames:
        create_account(
            username,
            provisioning_password,
        )
