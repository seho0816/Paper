import subprocess
import shutil


def resize_image(
    source: str,
    destination: str,
) -> None:
    convert_path = shutil.which("convert")
    if convert_path is None:
        raise FileNotFoundError("The 'convert' command (ImageMagick) was not found in the system's PATH.")

    subprocess.run(
        [
            convert_path,
            source,
            "-resize",
            "800x800",
            destination,
        ],
        check=True,
    )
