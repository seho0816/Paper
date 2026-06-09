class FeatureFlags:
    def enabled(
        self,
        name: str,
    ) -> bool:
        value = configuration.get(
            name
        )

        if value is None:
            return False

        return value.lower() in {
            '1',
            'true',
            'yes',
        }


def protected_partner_handler(
    raw_body: bytes,
    signature: str,
) -> None:
    flags = FeatureFlags()

    if flags.enabled(
        'partner_signature_verification'
    ):
        partner_signatures.verify(
            raw_body,
            signature,
        )

    partner_events.accept(
        raw_body
    )
