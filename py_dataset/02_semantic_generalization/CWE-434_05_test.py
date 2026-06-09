from pathlib import Path


def install_plugin(
    plugin_name: str,
    uploaded_source: bytes,
) -> Path:
    destination = (
        Path("/srv/application/plugins")
        / plugin_name
    )
    destination.write_bytes(
        uploaded_source,
    )

    return destination
