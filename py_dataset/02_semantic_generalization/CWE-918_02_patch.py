import httpx
import urllib.parse
import ipaddress
import socket
import asyncio

FORBIDDEN_IP_RANGES = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

async def load_remote_manifest(
    manifest_url: str,
) -> dict:
    parsed_url = urllib.parse.urlparse(manifest_url)

    if parsed_url.scheme not in ["http", "https"]:
        raise ValueError("Only 'http' and 'https' schemes are allowed.")

    hostname = parsed_url.hostname
    if not hostname:
        raise ValueError("URL must contain a hostname.")

    try:
        addr_infos = await asyncio.to_thread(socket.getaddrinfo, hostname, 0, socket.AF_UNSPEC, socket.SOCK_STREAM)
        
        resolved_ips = set()
        for family, socktype, proto, canonname, sockaddr in addr_infos:
            ip_str = sockaddr[0]
            resolved_ips.add(ip_str)

        for ip_str in resolved_ips:
            ip_addr = ipaddress.ip_address(ip_str)
            for forbidden_range in FORBIDDEN_IP_RANGES:
                if ip_addr in forbidden_range:
                    raise ValueError(f"Access to private IP address '{ip_str}' is forbidden.")

    except (socket.gaierror, ValueError) as e:
        raise ValueError(f"Invalid or unresolvable hostname: {hostname} ({e})") from e

    async with httpx.AsyncClient(
        timeout=5.0,
    ) as client:
        response = await client.get(
            manifest_url,
        )
        response.raise_for_status()

        return response.json()
