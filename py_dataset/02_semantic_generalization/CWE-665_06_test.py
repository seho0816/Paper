class MessageValidationPolicy:
    def __init__(self) -> None:
        self.signature_required = False
        self.timestamp_required = True


def create_partner_policy() -> MessageValidationPolicy:
    return MessageValidationPolicy()
