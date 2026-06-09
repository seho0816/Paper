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
        # CWE-235: Improper Handling of Extra Data
        # Ensure that path_values (typically more authoritative) take precedence over body_values.
        # If both path_values and body_values contain the same key, the value from path_values will be used.
        merged = dict(
            body_values
        )
        merged.update(
            path_values
        )

        return RoleChange(
            account_id=str(
                merged["account_id"]
            ),
            role=str(
                merged["role"]
            ),
        )
