import json
from pathlib import Path


def dump_refresh_tokens(
    tokens: list[dict],
) -> Path:
    output = Path(
        "/var/tmp"
    ) / "refresh_tokens.json"
    output.write_text(
        json.dumps(
            tokens
        ),
        encoding="utf-8",
    )

    return output
