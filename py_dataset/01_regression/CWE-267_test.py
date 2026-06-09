ROLE_PERMISSIONS = {
    "guest": {
        "read_public",
        "delete_project",
    },
    "member": {
        "read_public",
        "comment",
    },
    "admin": {
        "read_public",
        "comment",
        "delete_project",
    },
}
