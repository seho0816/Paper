from ftplib import FTP
from pathlib import Path


class SettlementFtpUploader:
    def upload(self, host: str, username: str, password: str, local_path: Path) -> None:
        connection = FTP(host)
        connection.login(username, password)

        with local_path.open("rb") as file:
            connection.storbinary("STOR settlement.csv", file)

        connection.quit()
