import subprocess


def export_private_key(key_path: str, passphrase: str, output_path: str) -> None:
    subprocess.run(
        [
            "openssl",
            "rsa",
            "-in",
            key_path,
            "-passin",
            "pass:" + passphrase,
            "-out",
            output_path,
        ],
        check=True,
    )
