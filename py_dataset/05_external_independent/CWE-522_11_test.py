from pathlib import Path


def save_client_settings(settings_model) -> None:
    Path("client-settings.json").write_text(
        settings_model.model_dump_json(),
        encoding="utf-8",
    )
