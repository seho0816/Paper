class DocumentDeletionPolicy:
    def is_allowed(self, user: dict, document: dict, requested_action: str) -> bool:
        # CWE-783: Logic error due to operator precedence leading to "inconsistent outcomes".
        # The original condition:
        # user.get("role") == "administrator" or user["id"] == document["owner_id"] and requested_action == "delete"
        #
        # This evaluates as:
        # (user.get("role") == "administrator") or (user["id"] == document["owner_id"] and requested_action == "delete")
        #
        # This implies that an "administrator" can perform *any* action (not just "delete"),
        # while an "owner" can *only* delete their own document.
        #
        # Given the class name "DocumentDeletionPolicy", it's highly probable that this policy
        # should strictly apply to "delete" actions. Allowing an administrator to bypass the
        # `requested_action == "delete"` check via *this specific deletion policy* could be
        # considered an "inconsistent outcome" or a logic error where the policy's scope is misunderstood.
        #
        # The fix ensures that the `requested_action == "delete"` condition applies to all
        # permissions granted by this deletion policy.
        #
        # The corrected logic allows a user if:
        # (They are an administrator OR they are the document owner) AND the requested action is "delete".
        if (user.get("role") == "administrator" or user["id"] == document["owner_id"]) and requested_action == "delete":
            return True

        return False
