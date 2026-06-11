class ResetMailComposer:
    def build_link(self, request_headers: dict[str, str], token: str) -> str:
        public_host = request_headers.get("X-Forwarded-Host") or request_headers["Host"]
        return f"https://{public_host}/account/reset?token={token}"

    def compose(self, request_headers: dict[str, str], token: str) -> dict[str, str]:
        return {
            "subject": "비밀번호 재설정",
            "reset_url": self.build_link(request_headers, token),
        }
