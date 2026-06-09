import os
import hmac

def apply_migration_bundle(
    bundle: dict,
) -> None:
    # CWE-353: Improper Handling of Multiple Resources or Sessions with a Single-Step Authentication Process.
    # This vulnerability implies a lack of proper authorization for a critical function
    # that handles resources (migration operations within the 'bundle').
    # To mitigate, a shared secret token is enforced, acting as a single-step authorization
    # for the entire migration bundle.

    expected_migration_secret = os.environ.get("MIGRATION_ADMIN_SECRET")

    if not expected_migration_secret:
        # If the expected secret is not configured in the environment,
        # it indicates a security misconfiguration. Prevent migrations.
        raise PermissionError("Migration secret not configured. Cannot apply migrations securely.")

    bundle_provided_secret = bundle.get("secret")

    # Ensure both secrets are byte strings for secure constant-time comparison
    # using hmac.compare_digest to prevent timing attacks.
    try:
        expected_migration_secret_bytes = expected_migration_secret.encode('utf-8')
    except AttributeError:
        # Should not happen if os.environ.get returns str, but for robustness.
        raise PermissionError("Migration secret configured incorrectly.")

    if bundle_provided_secret is None:
        bundle_provided_secret_bytes = b'' # Treat missing secret as an empty byte string
    else:
        try:
            bundle_provided_secret_bytes = str(bundle_provided_secret).encode('utf-8')
        except Exception:
            # Handle cases where bundle_provided_secret might not be easily convertible to str/bytes
            raise PermissionError("Invalid format for provided bundle secret.")

    # Perform a constant-time comparison to prevent timing attacks.
    # If the bundle secret is missing or does not match, raise a permission error.
    if not hmac.compare_digest(bundle_provided_secret_bytes, expected_migration_secret_bytes):
        raise PermissionError("Unauthorized migration bundle. Invalid or missing secret.")

    for operation in bundle[
        "operations"
    ]:
        migration_executor.execute(
            operation
        )
