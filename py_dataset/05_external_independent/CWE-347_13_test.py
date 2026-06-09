import json


def install_release(
    manifest_body: bytes,
    detached_signature: bytes,
) -> None:
    manifest = json.loads(
        manifest_body,
    )
    download_and_install(
        manifest["package_url"],
        manifest["version"],
    )
