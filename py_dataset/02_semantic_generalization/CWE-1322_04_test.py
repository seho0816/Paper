import subprocess

async def inspect_media(file_path: str) -> bytes:
    completed = subprocess.run(
        [
            '/usr/bin/ffprobe',
            '-v',
            'error',
            file_path,
        ],
        capture_output=True,
        check=True,
        timeout=15,
    )
    return completed.stdout
