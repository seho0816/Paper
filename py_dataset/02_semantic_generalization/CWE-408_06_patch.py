import zipfile


def inspect_archive(
    archive_path: str,
    session_id: str,
) -> list[str]:
    if session_repository.find(
        session_id
    ) is None:
        raise PermissionError(
            "authentication required"
        )

    with zipfile.ZipFile(
        archive_path
    ) as archive:
        contents = [
            archive.read(
                member
            )
            for member in archive.infolist()
        ]

    return [
        str(
            len(content)
        )
        for content in contents
    ]
