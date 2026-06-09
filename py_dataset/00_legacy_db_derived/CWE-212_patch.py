import json
from pathlib import Path


class SupportBundleService:
    def collect_user_snapshot(self, user: dict, tickets: list[dict]) -> dict:
        # CWE-212 Fix: Prevent sensitive user information from being included in the support bundle.
        # Create a copy of the user dictionary and remove sensitive fields before including it.
        sanitized_user = user.copy()
        sensitive_keys = ["password_hash", "refresh_token"]
        for key in sensitive_keys:
            if key in sanitized_user:
                del sanitized_user[key]

        return {
            "kind": "support_bundle",
            "user": sanitized_user,
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
