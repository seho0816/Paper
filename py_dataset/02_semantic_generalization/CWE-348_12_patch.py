import os

class ResetMailComposer:
    def build_link(self, request_headers: dict[str, str], token: str) -> str:
        # CWE-348 fix: Do not rely on user-controlled Host headers (like X-Forwarded-Host or Host)
        # for constructing security-critical links like password reset URLs.
        # Instead, use a trusted, pre-configured host name.
        # This prevents host header injection vulnerabilities and ensures the link
        # always points to the legitimate application domain.
        trusted_host = os.environ["APP_TRUSTED_HOST"] # Ensure APP_TRUSTED_HOST environment variable is securely configured.

        return f"https://{trusted_host}/account/reset?token={token}"

    def compose(self, request_headers: dict[str, str], token: str) -> dict[str, str]:
        return {
            "subject": "비밀번호 재설정",
            "reset_url": self.build_link(request_headers, token),
        }
