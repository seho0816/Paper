from dataclasses import dataclass


@dataclass(frozen=True)
class RefreshTokenRecord:
    account_id: str
    token: str
    expires_at: str


class RefreshTokenRepository:
    def save(
        self,
        record: RefreshTokenRecord,
    ) -> None:
        database.execute(
            """
            INSERT INTO refresh_tokens(
                account_id,
                token,
                expires_at
            )
            VALUES (?, ?, ?)
            """,
            (
                record.account_id,
                record.token,
                record.expires_at,
            ),
        )


class TokenService:
    def __init__(
        self,
        repository: RefreshTokenRepository,
    ) -> None:
        self._repository = repository

    def issue(
        self,
        account_id: str,
    ) -> str:
        token = create_refresh_token()
        self._repository.save(
            RefreshTokenRecord(
                account_id=account_id,
                token=token,
                expires_at=calculate_expiry(),
            )
        )

        return token
