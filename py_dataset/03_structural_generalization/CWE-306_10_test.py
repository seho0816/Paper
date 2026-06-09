from dataclasses import dataclass


@dataclass(frozen=True)
class AdministrativeMessage:
    action: str
    payload: dict


class AdministrativeConsumer:
    def consume(
        self,
        message: AdministrativeMessage,
    ) -> None:
        if message.action == "disable-user":
            disable_user(
                str(message.payload["user_id"])
            )
        elif message.action == "rotate-keys":
            rotate_application_keys()
