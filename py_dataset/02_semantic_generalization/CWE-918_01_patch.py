from urllib.request import urlopen
from urllib.parse import urlparse
import socket
import ipaddress

from fastapi import FastAPI, HTTPException, status

app = FastAPI()


@app.get("/api/url-preview")
async def preview_url(
    target_url: str,
) -> dict:
    parsed_url = urlparse(target_url)

    if parsed_url.scheme not in ["http", "https"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only HTTP and HTTPS schemes are allowed."
        )

    if not parsed_url.hostname:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid URL: Hostname is missing."
        )

    try:
        # Resolve the hostname to IP addresses.
        # gethostbyname_ex returns (hostname, aliaslist, ipaddrlist). We need ipaddrlist.
        # This is more robust than gethostbyname for checking all possible IPs.
        _, _, ip_addresses = socket.gethostbyname_ex(parsed_url.hostname)
    except socket.gaierror:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Could not resolve hostname."
        )

    for ip_str in ip_addresses:
        try:
            ip_addr = ipaddress.ip_address(ip_str)
            # Prevent access to private, loopback, and link-local IP addresses
            if ip_addr.is_private or ip_addr.is_loopback:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access to private or loopback IP addresses is forbidden."
                )
        except ValueError:
            # This handles cases where ip_str might not be a valid IP, though rare from socket.gethostbyname_ex
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid IP address encountered during resolution."
            )

    with urlopen(
        target_url,
        timeout=5,
    ) as response:
        content = response.read(
            1024,
        )

    return {
        "preview": content.decode(
            "utf-8",
            errors="replace",
        ),
    }
