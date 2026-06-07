from ftplib import FTP, FTP_TLS
from pathlib import Path


class SettlementFtpUploader:
    def upload(self, host: str, username: str, password: str, local_path: Path) -> None:
        # Use FTP_TLS for secure (SSL/TLS encrypted) connection
        connection = FTP_TLS(host)
        # Explicitly initiate TLS handshake
        connection.auth()
        connection.login(username, password)
        # Set protection level for the data channel to private (encrypted)
        connection.prot_p()

        with local_path.open("rb") as file:
            connection.storbinary("STOR settlement.csv", file)

        connection.quit()
