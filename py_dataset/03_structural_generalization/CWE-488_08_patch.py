class PrivateRoomHub:
    def __init__(self) -> None:
        self._last_private_message: dict | None = None
        self._connections: dict[str, object] = {}

    async def join(self, session_id: str, socket) -> None:
        self._connections[session_id] = socket
        # CWE-488: Exposed Data Element to Wrong Region.
        # Removing the logic that sends the last private message to any joining user.
        # A private message should only be sent to its intended recipient.
        # if self._last_private_message is not None:
        #     await socket.send_json(self._last_private_message)

    async def send_to_session(self, session_id: str, message: dict) -> None:
        # CWE-488: Exposed Data Element to Wrong Region.
        # Removing the assignment of a private message to a global variable.
        # This global variable was later used to expose the message to unintended recipients.
        # self._last_private_message = message
        socket = self._connections[session_id]
        await socket.send_json(message)
