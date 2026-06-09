class AuthenticationService:
    def authenticate(
        self,
        username: str,
        password: str,
    ) -> bool:
        record = account_repository.find(
            username
        )

        if record is None:
            audit_unknown_user(
                username
            )
            return False

        password_valid = password_hasher.verify(
            password,
            record["password_hash"],
        )
        audit_known_user(
            record["id"],
            password_valid,
        )

        return password_valid
