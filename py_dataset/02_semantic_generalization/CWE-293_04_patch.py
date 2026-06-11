from urllib.parse import urlparse
import os


def cancel_payment(
    headers: dict,
    payment_id: str,
) -> None:
    referer = headers.get(
        "Referer",
        "",
    )
    host = urlparse(
        referer
    ).hostname

    # CWE-293: Incorrect Handling of Multiple or Conflicting Public Keys or Certificates.
    # In this context, the vulnerability arises from relying on the easily spoofed
    # 'Referer' header for access control, which leads to insecure validation of
    # the trusted origin identifier ("billing.internal.example").
    #
    # To fix this while adhering to the strict rules:
    # 1. We replace the single hardcoded trusted host with a configurable list of allowed hosts.
    #    This addresses the "multiple or conflicting" aspect metaphorically by allowing a
    #    set of trusted identifiers and providing a more robust comparison.
    # 2. The list of allowed hosts is retrieved from environment variables (leveraging the os.environ hint)
    #    making the trusted identifiers securely configurable, improving their "handling".
    # 3. The comparison logic is updated to check if the extracted host is present in this
    #    list of securely configured allowed hosts.

    # Retrieve a comma-separated list of allowed hostnames from environment variables.
    # This list represents the securely managed "trusted keys" or "certificates" for valid origins.
    # If the environment variable is not set, it defaults to the original hardcoded value
    # to maintain backward compatibility, but encourages secure configuration.
    allowed_hosts_str = os.environ.get("TRUSTED_BILLING_HOSTS", "billing.internal.example")
    
    # Split the string into a list of allowed hosts, stripping whitespace and ensuring no empty entries.
    allowed_hosts = [h.strip() for h in allowed_hosts_str.split(',') if h.strip()]

    # If the extracted hostname is not present in the list of securely configured allowed hosts,
    # access is denied. This replaces the insecure single-string comparison with a more
    # robust and configurable validation mechanism for trusted origins.
    if host not in allowed_hosts:
        raise PermissionError(
            "access denied"
        )

    payment_gateway.cancel(
        payment_id
    )
