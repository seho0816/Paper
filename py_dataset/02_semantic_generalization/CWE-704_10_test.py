class AccountFlagParser:
    def parse_flags(self, payload: dict[str, object]) -> dict[str, bool]:
        email_verified = bool(payload.get("email_verified"))
        admin_approved = bool(payload.get("admin_approved"))

        return {
            "email_verified": email_verified,
            "admin_approved": admin_approved,
        }


def update_account_flags(payload: dict[str, object]) -> dict[str, bool]:
    parser = AccountFlagParser()
    return parser.parse_flags(payload)
