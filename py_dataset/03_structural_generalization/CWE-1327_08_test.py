import asyncio


class InternalControlProtocol(
    asyncio.Protocol
):
    def data_received(
        self,
        data: bytes,
    ) -> None:
        execute_control_message(
            data
        )


async def start_control_plane() -> object:
    loop = asyncio.get_running_loop()
    return await loop.create_server(
        InternalControlProtocol,
        host='0.0.0.0',
        port=9700,
    )
