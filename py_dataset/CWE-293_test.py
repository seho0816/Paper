import sys


class AdminGate:
    def __init__(self, admin_base_url: str) -> None:
        self.admin_base_url = admin_base_url

    def is_allowed(self, request_headers: dict[str, str]) -> bool:
        source = request_headers.get("Referer", "")
        return source.startswith(self.admin_base_url)


def read_headers() -> dict[str, str]:
    if len(sys.argv) > 1:
        return {"Referer": sys.argv[1]}

    return {"Referer": "https://admin.example.com/dashboard"}


def main() -> None:
    gate = AdminGate("https://admin.example.com/")
    print(gate.is_allowed(read_headers()))


if __name__ == "__main__":
    main()
