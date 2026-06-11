from urllib.parse import urlparse

def validate_origin(
    origin: str,
) -> bool:
    trusted_domain = "trusted.example"
    try:
        parsed_origin = urlparse(origin)
        hostname = parsed_origin.hostname

        if hostname is None:
            # The origin string could not be parsed into a valid hostname.
            # For HTTP Origin headers, a valid origin will always have a hostname.
            return False

        # Validate that the hostname is either the trusted domain itself
        # or a legitimate subdomain of the trusted domain.
        # This prevents various bypasses such as:
        # - "evil.com/trusted.example" (hostname would be "evil.com")
        # - "anothertrusted.example" (does not end with ".trusted.example")
        # - "trusted.example.evil.com" (does not end with ".trusted.example")
        # The `endswith` check automatically handles `www.trusted.example`, `api.trusted.example` etc.
        return hostname == trusted_domain or hostname.endswith("." + trusted_domain)

    except ValueError:
        # Catch potential ValueError if the origin string is severely malformed
        # and urlparse struggles with it.
        return False
    except Exception:
        # Catch any other unexpected exceptions during parsing or validation.
        return False
