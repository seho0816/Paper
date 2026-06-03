import json
from pathlib import Path


class SupportBundleService:
    def collect_user_snapshot(self, user: dict, tickets: list[dict]) -> dict:
        return {
            "kind": "support_bundle",
            "user": user,
            "tickets": tickets,
        }

    def write_bundle(self, bundle: dict, output_path: Path) -> Path:
        output_path.write_text(json.dumps(bundle, ensure_ascii=False), encoding="utf-8")
        return output_path


def main() -> None:
    user = {
        "id": "user-100",
        "email": "mube@example.com",
        "password_hash": "pbkdf2:sha256:secret",
        "refresh_token": "REFRESH-TOKEN",
    }
    service = SupportBundleService()
    bundle = service.collect_user_snapshot(user, [{"id": "T-1", "message": "help"}])
    print(service.write_bundle(bundle, Path("./support_bundle.json")))


if __name__ == "__main__":
    main()
