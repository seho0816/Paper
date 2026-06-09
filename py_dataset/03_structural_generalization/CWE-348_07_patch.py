import os
from dataclasses import dataclass


@dataclass(frozen=True)
class ProxyMetadata:
    forwarded_proto: str
    forwarded_host: str


class PublicUrlService:
    def build(
        self,
        metadata: ProxyMetadata,
        path: str,
    ) -> str:
        # Validate forwarded_proto against allowed schemes.
        # This prevents attackers from injecting arbitrary URL schemes.
        allowed_schemes = {"http", "https"}
        if metadata.forwarded_proto not in allowed_schemes:
            raise ValueError(
                f"Invalid protocol '{metadata.forwarded_proto}'. Must be one of {', '.join(allowed_schemes)}."
            )

        # Retrieve trusted hosts from environment variables.
        # This whitelist is critical for addressing CWE-348 by ensuring that
        # `metadata.forwarded_host` refers to a known, trusted source.
        # Example: ALLOWED_HOSTS="app.example.com,api.example.com:8080"
        trusted_hosts_str = os.environ.get("ALLOWED_HOSTS", "")
        
        # Split and clean trusted hosts, allowing for port numbers in the whitelist.
        # Convert to lowercase for case-insensitive comparison.
        trusted_hosts = {h.strip().lower() for h in trusted_hosts_str.split(',') if h.strip()}

        # If no trusted hosts are configured, the application cannot securely validate
        # the forwarded host, which is a critical misconfiguration for CWE-348.
        if not trusted_hosts:
            raise ValueError(
                "ALLOWED_HOSTS environment variable is not configured. Cannot validate host securely."
            )

        host = metadata.forwarded_host

        # Perform basic syntactic validation to prevent malicious injection into the host part.
        # A hostname (with optional port) should not contain characters that indicate
        # path separators, query strings, fragments, userinfo, or alternative schemes.
        if not host:
            raise ValueError("Forwarded host cannot be empty.")
        
        # Check for characters that would break out of the host context or inject malicious parts.
        # These include path separators ('/', '\'), query string delimiter ('?'), fragment identifier ('#'),
        # and userinfo separator ('@').
        if any(char in host for char in ('/', '?', '#', '@', '\\')):
            raise ValueError(f"Malformed host '{host}'. Contains invalid characters for a hostname/port.")
        
        # Additionally, explicitly check for scheme separators within the host,
        # which would indicate an attempt to inject a full URL or change the scheme.
        if '://' in host:
             raise ValueError(f"Malformed host '{host}'. Contains an invalid scheme separator.")

        # Normalize the incoming host for case-insensitive comparison with trusted_hosts.
        # We compare the exact string (including port if present) against the whitelist.
        incoming_host_normalized = host.lower()
        
        # Check if the requested host (normalized) is in the list of trusted hosts.
        if incoming_host_normalized not in trusted_hosts:
            raise ValueError(
                f"Untrusted host '{host}'. Must be one of {', '.join(trusted_hosts)}."
            )

        return (
            metadata.forwarded_proto
            + "://"
            + host  # Use the original casing from metadata after validation
            + path
        )
