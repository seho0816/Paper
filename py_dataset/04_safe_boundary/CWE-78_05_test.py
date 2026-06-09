import ipaddress
import subprocess


def ping_host(
    host: str,
) -> str:
    address = ipaddress.ip_address(
        host,
    )

    completed = subprocess.run(
        [
            "/bin/ping",
            "-c",
            "1",
            str(address),
        ],
        shell=False,
        capture_output=True,
        text=True,
        check=False,
        timeout=5,
    )

    return completed.stdout
