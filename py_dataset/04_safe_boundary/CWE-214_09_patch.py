import os
import subprocess


def run_signer(passphrase: str, document_path: str) -> None:
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, passphrase.encode("utf-8"))
        os.close(write_fd)
        write_fd = -1
        subprocess.run(
            ["document-signer", "--passphrase-fd", str(read_fd), document_path],
            pass_fds=(read_fd,),
            check=True,
        )
    finally:
        os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)

