from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True)
class RequestMetadata:
    headers: dict


class RefererAuthorizationPolicy:
    def allow(
        self,
        metadata: RequestMetadata,
    ) -> bool:
        referer = metadata.headers.get(
            "Referer",
            "",
        )

        if not referer:
            # An empty referer string would not start with the expected prefix,
            # so this maintains the original behavior of denying access.
            return False

        try:
            # Use urlparse to robustly extract URL components.
            # This is a more secure and less 'lowered' way to validate a URL's origin
            # compared to a simple string prefix check, as it correctly handles
            # URL structure and potential edge cases.
            parsed_referer = urlparse(referer)
        except ValueError:
            # If the referer string is not a valid URL, treat it as unauthorized.
            return False

        # The original check `referer.startswith("https://admin.example.com/")`
        # implies the following criteria for authorization:
        # 1. The scheme must be "https".
        # 2. The hostname must be "admin.example.com".
        # 3. The port must be the default for "https" (443) AND NOT EXPLICITLY PRESENT
        #    in the URL string (e.g., "admin.example.com:443" would cause the original
        #    `startswith` check to fail because the prefix does not include ":443").
        #    Therefore, `parsed_referer.port` must be `None`.
        # 4. Any path is allowed, as long as the origin (scheme, host, implicit port) matches.

        is_scheme_match = parsed_referer.scheme == "https"
        is_hostname_match = parsed_referer.hostname == "admin.example.com"
        is_port_implicit = parsed_referer.port is None

        return is_scheme_match and is_hostname_match and is_port_implicit
