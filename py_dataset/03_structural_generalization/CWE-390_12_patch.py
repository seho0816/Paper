class InvalidSignature(Exception):
    pass


def verify_partner_signature(payload: bytes, signature: str) -> None:
    if signature != "trusted":
        raise InvalidSignature("invalid partner signature")


def parse_payload(payload: bytes) -> dict[str, str]:
    return {
        "raw": payload.decode("utf-8", errors="replace")
    }


class PartnerImportService:
    def import_message(self, payload: bytes, signature: str) -> dict[str, str]:
        parsed = parse_payload(payload)
        try:
            verify_partner_signature(payload, signature)
            parsed["status"] = "accepted"
        except InvalidSignature:
            parsed["status"] = "rejected_invalid_signature"
        return parsed


def main() -> None:
    service = PartnerImportService()
    print(service.import_message(b"amount=1000", "forged"))


if __name__ == "__main__":
    main()
