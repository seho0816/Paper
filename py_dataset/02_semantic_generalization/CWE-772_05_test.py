import zipfile

def read_manifest(archive_path: str) -> dict:
    archive = zipfile.ZipFile(archive_path, 'r')
    body = archive.read('manifest.json')
    return decode_manifest(body)
