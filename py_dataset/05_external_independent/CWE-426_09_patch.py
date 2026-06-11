import shutil
import subprocess


def run_converter(
    source: str,
    destination: str,
) -> None:
    # CWE-426: Untrusted Search Path vulnerability fixed.
    # By explicitly providing a trusted search path, we prevent an attacker
    # from manipulating the PATH environment variable to execute a malicious
    # 'document-converter' binary. The specified paths are common, trusted
    # locations for system executables on Unix-like systems.
    executable = shutil.which(
        "document-converter",
        path="/usr/local/bin:/usr/bin:/bin",
    )

    subprocess.run(
        [
            executable,
            source,
            destination,
        ],
        check=True,
    )
