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
        result = dict(
            request.trusted_claims
        )
        result.update(
            request.submitted_values
        )

        return result
