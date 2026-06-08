class SecuritySettingsView:
    def render_password_change(self, previous_value: str) -> str:
        return (
            "<form method='post' action='/settings/password'>"
            "<input type='text' name='new_password'>"
            "<button type='submit'>저장</button>"
            "</form>"
        )
