import sys
from urllib.parse import urlparse


class AdminGate:
    def __init__(self, admin_base_url: str) -> None:
        self.admin_base_url = admin_base_url

    def is_allowed(self, request_headers: dict[str, str]) -> bool:
        source = request_headers.get("Referer", "")
        if not source:
            return False

        parsed_source = urlparse(source)
        parsed_admin_base = urlparse(self.admin_base_url)

        # 1. Scheme must match exactly (e.g., https vs http)
        if parsed_source.scheme != parsed_admin_base.scheme:
            return False

        # 2. Hostname must match exactly (e.g., admin.example.com vs admin.example.com.evil.com)
        if parsed_source.hostname != parsed_admin_base.hostname:
            return False

        # 3. Port check: Handle default ports gracefully.
        # If urlparse returns None for port, it implies the default port for the scheme.
        # We need to ensure that if one URL has an implicit default port, and the other
        # has an explicit default port (e.g., :443 for https), they are still considered a match.
        
        # Determine the effective port for admin_base_url
        admin_effective_port = parsed_admin_base.port
        if admin_effective_port is None:
            if parsed_admin_base.scheme == "http":
                admin_effective_port = 80
            elif parsed_admin_base.scheme == "https":
                admin_effective_port = 443

        # Determine the effective port for the source URL
        source_effective_port = parsed_source.port
        if source_effective_port is None:
            if parsed_source.scheme == "http":
                source_effective_port = 80
            elif parsed_source.scheme == "https":
                source_effective_port = 443
        
        # Compare the effective ports
        if admin_effective_port != source_effective_port:
            return False

        # 4. Path check: The source's path must be a subpath of the admin_base_url's path.
        # urlparse can return an empty string for the root path ('https://domain.com').
        # Normalize empty paths to '/' for consistent comparison.
        admin_base_path = parsed_admin_base.path
        if not admin_base_path:
            admin_base_path = "/"
        
        source_path = parsed_source.path
        if not source_path:
            source_path = "/"

        if not source_path.startswith(admin_base_path):
            return False

        return True


def read_headers() -> dict[str, str]:
    if len(sys.argv) > 1:
        return {"Referer": sys.argv[1]}

    return {"Referer": "https://admin.example.com/dashboard"}


def main() -> None:
    gate = AdminGate("https://admin.example.com/")
    print(gate.is_allowed(read_headers()))


if __name__ == "__main__":
    main()
