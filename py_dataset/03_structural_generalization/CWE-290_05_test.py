from dataclasses import dataclass


@dataclass(frozen=True)
class RequestContext:
    headers: dict


class IdentityResolver:
    def resolve(
        self,
        context: RequestContext,
    ) -> dict | None:
        username = context.headers.get(
            "X-Remote-User"
        )

        if not username:
            return None

        return account_repository.find(
            username
        )
