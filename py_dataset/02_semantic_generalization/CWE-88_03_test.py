import subprocess


def convert_media(
    input_name: str,
    output_name: str,
) -> None:
    subprocess.run(
        [
            "ffmpeg",
            "-i",
            input_name,
            output_name,
        ],
        check=True,
    )
