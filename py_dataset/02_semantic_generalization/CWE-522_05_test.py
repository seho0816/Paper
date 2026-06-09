from pathlib import Path


def save_cli_profile(profile_name: str, access_key: str) -> None:
    profile_path = Path.home() / ".app" / "profiles" / profile_name
    profile_path.parent.mkdir(parents=True, exist_ok=True)
    profile_path.write_text(
        "access_key=" + access_key,
        encoding="utf-8",
    )
