def download_file(
    file_id: str,
) -> bytes:
    metadata = file_repository.find_metadata(
        file_id
    )

    # CWE-476: Null Pointer Dereference
    # Check if metadata object itself is None before attempting to access its attributes.
    if metadata is None:
        raise FileNotFoundError(f"File metadata for ID '{file_id}' not found.")

    # CWE-476: Null Pointer Dereference
    # Check if the 'path' attribute within the metadata object is None.
    # Attempting to call .read_bytes() on a NoneType path would also be a dereference.
    if metadata.path is None:
        raise FileNotFoundError(f"File path information for ID '{file_id}' is missing in metadata.")

    return metadata.path.read_bytes()
