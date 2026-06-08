class SecuritySettingsView:
    def render_password_change(self, previous_value: str) -> str:
        return (
            "<form method='post' action='/settings/password'>"
            f"<input type='text' name='new_password' value='{previous_value}'>"
            "<button type='submit'>저장</button>"
            "</form>"
        )
