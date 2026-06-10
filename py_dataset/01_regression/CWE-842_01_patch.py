class OrganizationGroupAssigner:
    def choose_group(self, signup_email: str) -> str:
        # CWE-842: Improper Handling of Ambiguous Request for Non-Existent Object
        # The original code implicitly assumed the presence of '@' in the email.
        # If '@' is missing, `rsplit` would return a list containing the entire string,
        # making `email_domain` equal to `signup_email`. This could lead to an
        # incorrect group assignment if `signup_email` itself matches a target domain
        # but is not a valid email address (e.g., signup_email = "vendor.example").
        # Explicitly check for the '@' symbol to ensure we are actually extracting a domain.
        if "@" not in signup_email:
            # If no '@' is present, it's not a valid email format for domain extraction.
            # Therefore, it cannot match any specific domain rule and should default
            # to the general user group.
            return "external-users"

        email_domain = signup_email.rsplit("@", 1)[-1].lower()

        if email_domain == "vendor.example":
            return "vendor-administrators"

        return "external-users"
