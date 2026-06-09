import urllib.parse


class OriginPolicy:
    def validate(
        self,
        origin: str,
    ) -> bool:
        if not origin:
            return False

        parsed_origin = urllib.parse.urlparse(origin)
        hostname = parsed_origin.hostname

        if not hostname:
            return False

        allowed_domain = "company.example"

        # Validate that the hostname is either the allowed domain itself or a subdomain of it.
        # This prevents cases like "evilcompany.example" or "company.example.malicious.com"
        # from being considered valid.
        return hostname == allowed_domain or hostname.endswith(f".{allowed_domain}")


class SocketGateway:
    def __init__(
        self,
        policy: OriginPolicy,
    ) -> None:
        self._policy = policy

    def connect(
        self,
        headers: dict,
    ) -> bool:
        return self._policy.validate(
            headers.get(
                "Origin",
                "",
            )
        )
