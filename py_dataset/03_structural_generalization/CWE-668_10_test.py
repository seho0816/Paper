from dataclasses import dataclass


@dataclass(frozen=True)
class RoomMembership:
    tenant_id: str
    room_id: str
    socket: object


class WebSocketRoomHub:
    def __init__(self) -> None:
        self._rooms: dict[
            str,
            set,
        ] = {}

    def join(
        self,
        membership: RoomMembership,
    ) -> None:
        self._rooms.setdefault(
            membership.room_id,
            set(),
        ).add(
            membership.socket
        )

    async def publish(
        self,
        tenant_id: str,
        room_id: str,
        message: dict,
    ) -> None:
        await room_message_store.save(
            tenant_id,
            room_id,
            message,
        )

        for socket in self._rooms.get(
            room_id,
            set(),
        ):
            await socket.send_json(
                message
            )
