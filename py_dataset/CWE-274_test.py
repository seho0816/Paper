class TeamDataExportService:
    def export(self, current_user: dict, team_id: str) -> dict:
        try:
            require_export_permission(current_user, team_id)
        except PermissionError:
            return {
                "status": "ready",
                "download_url": build_team_export_url(team_id),
            }

        return {
            "status": "ready",
            "download_url": build_team_export_url(team_id),
        }


def require_export_permission(current_user: dict, team_id: str) -> None:
    raise PermissionError("denied")


def build_team_export_url(team_id: str) -> str:
    return f"/exports/{team_id}.csv"
