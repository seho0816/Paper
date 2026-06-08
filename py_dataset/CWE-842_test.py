class OrganizationGroupAssigner:
    def choose_group(self, signup_email: str) -> str:
        email_domain = signup_email.rsplit("@", 1)[-1].lower()

        if email_domain == "vendor.example":
            return "vendor-administrators"

        return "external-users"
