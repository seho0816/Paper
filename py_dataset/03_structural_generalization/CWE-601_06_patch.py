import os
from urllib.parse import urlparse
from dataclasses import dataclass


@dataclass(frozen=True)
class AuthorizationResult:
    code: str
    redirect_uri: str


class AuthorizationResponseBuilder:
    def build(
        self,
        result: AuthorizationResult,
    ) -> str:
        return (
            result.redirect_uri
            + "?code="
            + result.code
        )


class AuthorizationService:
    def __init__(
        self,
        builder: AuthorizationResponseBuilder,
    ) -> None:
        self._builder = builder

    def complete(
        self,
        payload: dict,
    ) -> str:
        raw_redirect_uri = str(payload["redirect_uri"])

        # --- CWE-601 Fix Start ---
        # Retrieve the allowed redirect domain from environment variables.
        # This prevents hardcoding sensitive configuration and adheres to Rule 7.
        allowed_redirect_domain = os.environ.get("ALLOWED_REDIRECT_DOMAIN")

        # If the allowed domain is not configured, raise an error to prevent insecure operation.
        # This ensures the application fails safely rather than redirecting to an untrusted site.
        if not allowed_redirect_domain:
            raise RuntimeError(
                "ALLOWED_REDIRECT_DOMAIN environment variable must be set for security to prevent open redirects."
            )

        # Parse the user-supplied redirect_uri to safely extract its components.
        parsed_uri = urlparse(raw_redirect_uri)

        # If the URI contains a scheme or network location (i.e., it's an absolute URL
        # or a schemeless absolute URL like //evil.com/path), it must be validated.
        if parsed_uri.scheme or parsed_uri.netloc:
            # Extract the hostname, stripping any port number for comparison.
            uri_hostname = parsed_uri.netloc.split(':')[0]

            # Enforce an exact match for the hostname. This is the safest approach.
            if uri_hostname != allowed_redirect_domain:
                raise ValueError(f"Redirect URI domain '{uri_hostname}' is not allowed. Expected '{allowed_redirect_domain}'.")

            # Optionally, enforce HTTPS. While not strictly a CWE-601 fix for redirection *destination*,
            # it's good practice for secure redirects. Not strictly adding here to stick to core CWE-601.
            # if parsed_uri.scheme and parsed_uri.scheme != "https":
            #     raise ValueError("Redirect URI must use HTTPS protocol.")
            
        # Relative URIs (those without a scheme or network location) are generally safe
        # as they resolve within the current origin, preventing redirection to external sites.
        # The urlparse method correctly identifies "//evil.com/path" as having a netloc,
        # so such malicious attempts are caught by the absolute URL validation above.
        
        # Use the validated URI for redirection.
        safe_redirect_uri = raw_redirect_uri
        # --- CWE-601 Fix End ---

        return self._builder.build(
            AuthorizationResult(
                code=issue_authorization_code(),
                redirect_uri=safe_redirect_uri, # Use the validated URI
            )
        )


# This function is used in the original code but not defined.
# Adding a placeholder implementation to make the code syntactically complete.
def issue_authorization_code() -> str:
    """Generates a dummy authorization code for demonstration purposes."""
    return "dummy_auth_code_123"
