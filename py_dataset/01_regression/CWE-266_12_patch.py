class MemberRegistrationService:
    def register(self, email: str, password_hash: str) -> dict:
        new_member = {
            "email": email,
            "password_hash": password_hash,
            "role": "user",
            "enabled": True,
        }
        persist_member(new_member)
        return new_member


def persist_member(member: dict) -> None:
    print(member["email"], member["role"])
