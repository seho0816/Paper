from dataclasses import dataclass


@dataclass(frozen=True)
class RequestContext:
    trusted_claims: dict
    submitted_values: dict


class ContextAssembler:
    def assemble(
        self,
        request: RequestContext,
    ) -> dict:
        # CWE-349: Acceptance of Extraneous Untrusted Data.
        # Ensure that trusted claims take precedence over submitted values
        # to prevent untrusted data from overwriting trusted information.
        # Dictionary unpacking {**a, **b} prioritizes keys from b if they
        # also exist in a. By placing trusted_claims last, its values
        # will override any conflicting keys from submitted_values.
        result = {**request.submitted_values, **request.trusted_claims}

        return result
