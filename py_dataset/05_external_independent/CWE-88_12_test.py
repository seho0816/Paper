import subprocess


def resize_image(
    input_path: str,
    output_path: str,
) -> None:
    subprocess.run(
        [
            "convert",
            input_path,
            "-resize",
            "400x400",
            output_path,
        ],
        check=True,
    )
