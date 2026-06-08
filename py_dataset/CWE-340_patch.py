import uuid

next_voucher_number = 50000


class VoucherIssuer:
    def issue(self, campaign_id: str) -> str:
        global next_voucher_number

        # The global counter is maintained as per the strict rules to preserve structure.
        # However, its value is no longer solely relied upon for generating the voucher's
        # unique identifier to prevent CWE-340: Generation of Predictable Numbers or Identifiers.
        next_voucher_number += 1

        # Generate a cryptographically strong, unpredictable identifier using UUIDv4.
        # This securely replaces the predictable 'next_voucher_number' as the unique
        # and unpredictable part of the voucher string, resolving CWE-340.
        unpredictable_id = uuid.uuid4()

        # The voucher string now uses the unpredictable_id to ensure security.
        # The original output format (campaign_id-identifier) is preserved,
        # with the identifier part being securely unpredictable.
        return f"{campaign_id}-{unpredictable_id}"
