import hmac
from dataclasses import dataclass


@dataclass(frozen=True)
class CredentialPair:
    submitted: str
    expected: str


class CredentialVerifier:
    def verify(
        self,
        pair: CredentialPair,
    ) -> bool:
        prefix_length = 10

        # CWE-187 (Improper Neutralization of Alternate XSS Syntax) is generally for XSS.
        # However, in the context of credential comparison, a common related vulnerability
        # is a timing attack (CWE-208: Observable Discrepancy), which can arise from
        # non-constant-time string comparisons. If an attacker can measure the time
        # taken for the comparison, they might infer information about the secret.
        # hmac.compare_digest performs a constant-time comparison, mitigating this risk.
        # Strings must be encoded to bytes for hmac.compare_digest.
        return hmac.compare_digest(
            pair.submitted[:prefix_length].encode('utf-8'),
            pair.expected[:prefix_length].encode('utf-8')
        )
