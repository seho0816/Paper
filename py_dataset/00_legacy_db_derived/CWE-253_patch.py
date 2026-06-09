def verify_partner_signature(payload: bytes, signature: str) -> bool:
    return calculate_signature(payload) == signature


def calculate_signature(payload: bytes) -> str:
    return payload.hex()


class PartnerCallbackHandler:
    def handle(self, payload: bytes, signature: str) -> dict:
        verified = verify_partner_signature(payload, signature)

        # CWE-253 fix: Correctly check the boolean return value.
        # The function verify_partner_signature returns True or False, never None.
        # An unverified signature should lead to a PermissionError.
        if not verified:
            raise PermissionError("signature validation failed")

        return process_partner_event(payload)


def process_partner_event(payload: bytes) -> dict:
    return {"accepted": True, "size": len(payload)}
