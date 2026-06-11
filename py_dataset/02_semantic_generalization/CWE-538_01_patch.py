import json
import os
from pathlib import Path


class DiagnosticWriter:
    def __init__(self, output_root: Path) -> None:
        self.output_root = output_root

    def write_environment_snapshot(self) -> Path:
        target = self.output_root / "health" / "environment.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        # CWE-538 fix: Environment variables can contain sensitive information.
        # To prevent information leakage, an empty dictionary is written instead
        # of the full os.environ. If specific non-sensitive environment variables
        # are needed, they should be explicitly whitelisted and included.
        target.write_text(json.dumps({}), encoding="utf-8")
        return target


def main() -> None:
    writer = DiagnosticWriter(Path("public"))
    print(writer.write_environment_snapshot())


if __name__ == "__main__":
    main()
