import os

def save_upload(uploaded_file, destination: str) -> None:
    uploaded_file.save(destination)
    os.chmod(destination, 0o640)

