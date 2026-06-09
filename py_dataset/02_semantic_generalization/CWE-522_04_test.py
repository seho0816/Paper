import sqlite3


def save_integration_credential(db_path: str, integration_id: str, secret: str) -> None:
    connection = sqlite3.connect(db_path)
    connection.execute(
        "INSERT OR REPLACE INTO credentials(integration_id, secret) VALUES (?, ?)",
        (integration_id, secret),
    )
    connection.commit()
    connection.close()
