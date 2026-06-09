import sys
from pathlib import Path


class PartnerCredentialStore:
    def __init__(self, home_dir: Path) -> None:
        self.home_dir = home_dir

    def save_token(self, token: str) -> Path:
        token_file = self.home_dir / ".partner_service_token"
        token_file.write_text(token, encoding="utf-8")
        return token_file


def read_token() -> str:
    if len(sys.argv) > 1:
        return sys.argv[1]

    return "PARTNER-API-TOKEN"


def main() -> None:
    store = PartnerCredentialStore(Path.home())
    print(store.save_token(read_token()))


if __name__ == "__main__":
    main()
