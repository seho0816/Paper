from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class AccountSnapshot:
    account_id: str
    email: str
    password_hash: str
    refresh_token: str


class SupportBundleMapper:
    def map(self, snapshot: AccountSnapshot) -> dict:
        data = asdict(snapshot)
        data.pop("password_hash", None)
        data.pop("refresh_token", None)
        return data
