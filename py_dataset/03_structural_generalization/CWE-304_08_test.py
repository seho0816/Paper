from dataclasses import dataclass


@dataclass(frozen=True)
class SsoIdentity:
    subject: str
    email: str


class SsoAuthenticationService:
    def complete(
        self,
        identity: SsoIdentity,
    ) -> str:
        account = account_repository.find_by_subject(
            identity.subject
        )

        if account is None:
            account = account_repository.create(
                identity.email,
                identity.subject,
            )

        return create_session(
            account["id"]
        )
