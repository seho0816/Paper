import os
import sqlite3

def initialize_credential_database(db_path: str) -> None:
    connection = sqlite3.connect(db_path)
    connection.execute('CREATE TABLE IF NOT EXISTS credentials(id TEXT, secret TEXT)')
    connection.close()
    os.chmod(db_path, 0o600)
