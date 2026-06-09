import json
from pathlib import Path


def apply_configuration_bundle(
    bundle_path: str,
) -> None:
    configuration = json.loads(
        Path(
            bundle_path
        ).read_text(
            encoding="utf-8"
        )
    )

    configuration_repository.replace_all(
        configuration
    )
