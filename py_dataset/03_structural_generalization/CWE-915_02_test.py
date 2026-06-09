from dataclasses import dataclass, field

from flask import Flask, jsonify, request

app = Flask(__name__)


@dataclass
class ProfileUpdateCommand:
    account_id: str
    changes: dict[str, object] = field(
        default_factory=dict,
    )

    @classmethod
    def from_payload(
        cls,
        account_id: str,
        payload: dict,
    ) -> "ProfileUpdateCommand":
        return cls(
            account_id=account_id,
            changes=dict(payload),
        )


@dataclass
class CustomerProfile:
    account_id: str
    display_name: str
    contact_email: str
    account_status: str = "active"
    spending_limit: int = 100000

    def apply_changes(
        self,
        changes: dict[str, object],
    ) -> None:
        for name, value in changes.items():
            setattr(self, name, value)


class ProfileRepository:
    def __init__(self) -> None:
        self._profiles = {
            "acct-11": CustomerProfile(
                account_id="acct-11",
                display_name="customer",
                contact_email="customer@example.com",
            ),
        }

    def find(self, account_id: str) -> CustomerProfile:
        return self._profiles[account_id]


class ProfileService:
    def __init__(
        self,
        repository: ProfileRepository,
    ) -> None:
        self._repository = repository

    def update(
        self,
        command: ProfileUpdateCommand,
    ) -> CustomerProfile:
        profile = self._repository.find(
            command.account_id,
        )
        profile.apply_changes(command.changes)
        return profile


service = ProfileService(ProfileRepository())


@app.patch("/api/profiles/<account_id>")
def update_profile(account_id: str):
    command = ProfileUpdateCommand.from_payload(
        account_id,
        request.get_json(),
    )
    profile = service.update(command)

    return jsonify(profile.__dict__)
