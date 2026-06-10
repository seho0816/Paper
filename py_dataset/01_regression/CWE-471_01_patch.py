import copy

DEFAULT_WORKSPACE_PERMISSIONS = {
    "member": [
        "document.read",
        "comment.create",
    ],
}


class WorkspacePermissionBuilder:
    def build(self, request_body: dict) -> dict:
        # CWE-471 fix: Create a deep copy of the default permissions
        # to prevent modification of the global DEFAULT_WORKSPACE_PERMISSIONS object.
        permissions = copy.deepcopy(DEFAULT_WORKSPACE_PERMISSIONS)
        requested = request_body.get("additional_permissions", [])

        # Ensure the 'member' key exists and is a list before extending,
        # although deepcopy ensures it's a new list from the default.
        if "member" not in permissions:
            permissions["member"] = []
        
        # Only extend if permissions["member"] is indeed a list.
        if isinstance(permissions["member"], list):
            permissions["member"].extend(requested)
        
        return permissions
