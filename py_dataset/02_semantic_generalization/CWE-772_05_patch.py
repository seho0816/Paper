import zipfile

def read_manifest(archive_path: str) -> dict:
    with zipfile.ZipFile(archive_path, 'r') as archive:
        body = archive.read('manifest.json')
    return decode_manifest(body)
