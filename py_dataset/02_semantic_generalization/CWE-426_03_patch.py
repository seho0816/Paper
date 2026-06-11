import subprocess


def convert_certificate(
    input_path: str,
    output_path: str,
) -> None:
    subprocess.run(
        [
            "/usr/bin/openssl",
            "x509",
            "-in",
            input_path,
            "-out",
            output_path,
        ],
        check=True,
    )
