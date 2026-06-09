class RequestContextBuilder:
    def build(self, verified_claims: dict, request_payload: dict) -> dict:
        # CWE-349: Permitting a Mechanism to Bypass the 'Least Privilege' ACL
        # The original code merged dictionaries with request_payload overwriting verified_claims.
        # This could allow an attacker to forge or escalate privileges by supplying a
        # sensitive claim (like 'role') in the request_payload that overrides the
        # verified claim.
        # To fix this, the merge order is reversed to ensure that trusted 'verified_claims'
        # take precedence over potentially untrusted 'request_payload' for common keys.
        effective_context = {
            **request_payload, # Start with request payload data
            **verified_claims, # Verified claims take precedence for conflicting keys
        }

        return effective_context


def resolve_effective_role(verified_claims: dict, request_payload: dict) -> str:
    builder = RequestContextBuilder()
    context = builder.build(verified_claims, request_payload)
    return context["role"]
