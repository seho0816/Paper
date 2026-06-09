from pathlib import Path
import shutil


def publish_diagnostic_config(config_path: str) -> str:
    target = Path("public") / "diagnostics" / "application.env"
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(config_path, target)
    return "/diagnostics/application.env"
