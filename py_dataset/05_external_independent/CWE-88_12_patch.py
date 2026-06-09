import subprocess


def resize_image(
    input_path: str,
    output_path: str,
) -> None:
    subprocess.run(
        [
            "convert",
            "-resize",
            "400x400",
            "--",  # Treat subsequent arguments as filenames, preventing argument injection (CWE-88)
            input_path,
            output_path,
        ],
        check=True,
    )
