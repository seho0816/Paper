from dataclasses import dataclass
import urllib.parse
import ipaddress
import socket

import aiohttp


@dataclass(frozen=True)
class AvatarImportRequest:
    profile_id: str
    avatar_url: str


class AvatarDownloader:
    async def download(
        self,
        request: AvatarImportRequest,
    ) -> bytes:
        # Validate the avatar_url to prevent Server-Side Request Forgery (SSRF)
        parsed_url = urllib.parse.urlparse(request.avatar_url)

        # 1. Scheme validation: Only allow HTTP and HTTPS
        if parsed_url.scheme not in ('http', 'https'):
            raise ValueError("Only HTTP and HTTPS schemes are allowed for avatar URLs.")

        # 2. Hostname existence check
        if not parsed_url.hostname:
            raise ValueError("URL must contain a valid hostname.")

        try:
            # 3. Resolve hostname to an IP address
            # This step can prevent DNS rebinding attacks to some extent
            # by fixing the IP before the actual request.
            # socket.gethostbyname raises socket.gaierror for invalid hostnames.
            ip_string = socket.gethostbyname(parsed_url.hostname)
            ip_addr = ipaddress.ip_address(ip_string)

            # 4. IP address validation: Block access to private, loopback,
            # link-local, multicast, and reserved IP ranges.
            if (
                ip_addr.is_private or
                ip_addr.is_loopback or
                ip_addr.is_link_local or
                ip_addr.is_multicast or
                ip_addr.is_reserved
            ):
                raise ValueError("Access to private, loopback, or special IP addresses is forbidden.")

        except (socket.gaierror, ValueError) as e:
            # Catch socket.gaierror for DNS resolution failures and
            # ValueError for ipaddress parsing or our custom validation failures.
            raise ValueError(f"Invalid or forbidden URL hostname: {parsed_url.hostname}") from e

        async with aiohttp.ClientSession() as session:
            async with session.get(
                request.avatar_url,
            ) as response:
                response.raise_for_status()  # Raise an exception for bad status codes
                return await response.read()


class ProfileService:
    def __init__(
        self,
        downloader: AvatarDownloader,
    ) -> None:
        self._downloader = downloader

    async def import_avatar(
        self,
        payload: dict,
    ) -> bytes:
        request = AvatarImportRequest(
            profile_id=str(
                payload["profile_id"],
            ),
            avatar_url=str(
                payload["avatar_url"],
            ),
        )

        return await self._downloader.download(
            request,
        )
