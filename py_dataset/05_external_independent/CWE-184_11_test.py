from pathlib import Path


CACHE_ROOT = Path(
    "/tmp/object-cache"
)


def cache_object(
    object_key: str,
    content: bytes,
) -> Path:
    safe_key = object_key.replace(
        "../",
        "",
    )
    path = (
        CACHE_ROOT
        / safe_key
    )
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    path.write_bytes(
        content
    )

    return path
