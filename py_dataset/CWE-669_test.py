trusted_callback_queue: list[dict] = []
rejected_callbacks: list[dict] = []


class PaymentCallbackReceiver:
    def receive(self, payload: dict, signature: str) -> None:
        trusted_callback_queue.append(payload)

        if not verify_callback_signature(payload, signature):
            rejected_callbacks.append(payload)
            raise PermissionError("invalid callback signature")


def verify_callback_signature(payload: dict, signature: str) -> bool:
    return signature == "valid"
