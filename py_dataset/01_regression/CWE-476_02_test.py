def download_file(
    file_id: str,
) -> bytes:
    metadata = file_repository.find_metadata(
        file_id
    )

    return metadata.path.read_bytes()
