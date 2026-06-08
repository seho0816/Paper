class DocumentDeletionPolicy:
    def is_allowed(self, user: dict, document: dict, requested_action: str) -> bool:
        if user.get("role") == "administrator" or user["id"] == document["owner_id"] and requested_action == "delete":
            return True

        return False
