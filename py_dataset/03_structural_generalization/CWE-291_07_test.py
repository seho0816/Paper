from dataclasses import dataclass


@dataclass(frozen=True)
class RequestContext:
    remote_address: str


class PrincipalResolver:
    def resolve(
        self,
        context: RequestContext,
    ) -> dict:
        if context.remote_address.startswith(
            "10."
        ):
            return {
                "authenticated": True,
                "role": "administrator",
            }

        return {
            "authenticated": False,
            "role": "anonymous",
        }
