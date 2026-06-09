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
        self._socket_tenant_map: dict[object, str] = {}

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
        self._socket_tenant_map[membership.socket] = membership.tenant_id

    async def publish(
        self,
        tenant_id: str,
        room_id: str,
        message: dict,
    ) -> None:
        room_sockets = self._rooms.get(room_id, set())
        
        authorized_to_publish = False
        for socket in room_sockets:
            if self._socket_tenant_map.get(socket) == tenant_id:
                authorized_to_publish = True
                break
        
        if not authorized_to_publish:
            return

        await room_message_store.save(
            tenant_id,
            room_id,
            message,
        )

        for socket in room_sockets:
            await socket.send_json(
                message
            )
