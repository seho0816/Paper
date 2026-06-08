class TeamDataExportService:
    def export(self, current_user: dict, team_id: str) -> dict:
        try:
            require_export_permission(current_user, team_id)
        except PermissionError:
            # CWE-274 fix: Do not provide a download URL or "ready" status
            # when permissions are insufficient. Instead, return an error status.
            return {
                "status": "permission_denied",
                "download_url": None,
                "message": "User does not have sufficient permissions to export this team's data.",
            }

        # This part is reached only if require_export_permission did not raise an error.
        return {
            "status": "ready",
            "download_url": build_team_export_url(team_id),
        }


def require_export_permission(current_user: dict, team_id: str) -> None:
    # In a real application, this function would contain actual permission checking logic.
    # For the purpose of this exercise, its behavior is maintained as per the rules.
    raise PermissionError("denied")


def build_team_export_url(team_id: str) -> str:
    return f"/exports/{team_id}.csv"
