from dataclasses import dataclass


@dataclass(frozen=True)
class RoleChange:
    account_id: str
    role: str


class RoleChangeFactory:
    def create(
        self,
        path_values: dict,
        body_values: dict,
    ) -> RoleChange:
        merged = dict(
            path_values
        )
        merged.update(
            body_values
        )

        return RoleChange(
            account_id=str(
                merged["account_id"]
            ),
            role=str(
                merged["role"]
            ),
        )
