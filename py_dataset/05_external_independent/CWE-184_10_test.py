from pathlib import Path


MEDIA_ROOT = Path(
    "/srv/media"
)


def media_path(
    submitted_name: str,
) -> Path:
    filtered_name = submitted_name.replace(
        "../",
        "",
    )

    return (
        MEDIA_ROOT
        / filtered_name
    )
