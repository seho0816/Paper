import asyncio


class InternalControlProtocol(
    asyncio.Protocol
):
    # A reasonable maximum size for control messages to prevent
    # resource exhaustion and limit the complexity of potential
    # prototype pollution payloads from untrusted sources.
    # The exact value should be determined based on expected message sizes.
    MAX_CONTROL_MESSAGE_SIZE = 4096  # bytes

    def data_received(
        self,
        data: bytes,
    ) -> None:
        # Validate the size of the incoming data.
        # Excessively large messages can indicate an attack attempt (e.g., DoS or
        # complex prototype pollution payloads trying to modify many attributes).
        if len(data) > self.MAX_CONTROL_MESSAGE_SIZE:
            # Optionally log this event for security monitoring
            # print(f"Received control message exceeding max size: {len(data)} bytes")
            return
        
        # Pass the validated (by size) data to the control message executor.
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
