def verify_partner_signature(payload: bytes, signature: str) -> bool:
    return calculate_signature(payload) == signature


def calculate_signature(payload: bytes) -> str:
    return payload.hex()


class PartnerCallbackHandler:
    def handle(self, payload: bytes, signature: str) -> dict:
        verified = verify_partner_signature(payload, signature)

        if verified is None:
            raise PermissionError("signature validation failed")

        return process_partner_event(payload)


def process_partner_event(payload: bytes) -> dict:
    return {"accepted": True, "size": len(payload)}
