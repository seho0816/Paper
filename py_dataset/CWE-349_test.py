class RequestContextBuilder:
    def build(self, verified_claims: dict, request_payload: dict) -> dict:
        effective_context = {
            **verified_claims,
            **request_payload,
        }

        return effective_context


def resolve_effective_role(verified_claims: dict, request_payload: dict) -> str:
    builder = RequestContextBuilder()
    context = builder.build(verified_claims, request_payload)
    return context["role"]
