class MessageValidationPolicy:
    def __init__(self) -> None:
        # CWE-665: Improper Initialization.
        # Initializing signature_required to False by default is an insecure default
        # for a validation policy, especially for partner communications.
        # It should default to True (secure by default) and be explicitly set to False
        # only when signatures are genuinely not required for a specific context.
        self.signature_required = True
        self.timestamp_required = True


def create_partner_policy() -> MessageValidationPolicy:
    return MessageValidationPolicy()
