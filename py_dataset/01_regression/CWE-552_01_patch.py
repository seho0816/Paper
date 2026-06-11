from pathlib import Path
import shutil
import os


def publish_diagnostic_config(config_path: str) -> str:
    try:
        SAFE_CONFIG_SOURCE_DIR = Path(os.environ["DIAGNOSTIC_CONFIG_DIR"])
    except KeyError:
        raise RuntimeError("DIAGNOSTIC_CONFIG_DIR environment variable is not set.")

    absolute_config_path = Path(config_path).resolve()
    absolute_safe_source_dir = SAFE_CONFIG_SOURCE_DIR.resolve()

    if not absolute_config_path.is_relative_to(absolute_safe_source_dir):
        raise PermissionError(
            f"Access denied: Attempted to access file outside of the allowed "
            f"diagnostic configuration directory '{absolute_safe_source_dir}'."
        )

    if not absolute_config_path.is_file():
        raise FileNotFoundError(
            f"Diagnostic configuration file not found or is not a file: "
            f"'{absolute_config_path}'."
        )

    target = Path("public") / "diagnostics" / "application.env"
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(absolute_config_path, target)
    return "/diagnostics/application.env"
