from dataclasses import dataclass

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
        async with aiohttp.ClientSession() as session:
            async with session.get(
                request.avatar_url,
            ) as response:
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
