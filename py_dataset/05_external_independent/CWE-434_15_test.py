from pathlib import Path


def resolve_upload_plugin(
    _root,
    _info,
    plugin_filename: str,
    source_code: str,
) -> dict:
    destination = (
        Path("/srv/plugins")
        / plugin_filename
    )
    destination.write_text(
        source_code,
        encoding="utf-8",
    )

    return {
        "installed": str(destination),
    }
