DEFAULT_WORKSPACE_PERMISSIONS = {
    "member": [
        "document.read",
        "comment.create",
    ],
}


class WorkspacePermissionBuilder:
    def build(self, request_body: dict) -> dict:
        permissions = DEFAULT_WORKSPACE_PERMISSIONS
        requested = request_body.get("additional_permissions", [])

        permissions["member"].extend(requested)
        return permissions
