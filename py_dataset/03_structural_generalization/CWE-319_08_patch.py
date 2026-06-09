from dataclasses import dataclass
from ftplib import FTP_TLS
from pathlib import Path


@dataclass(frozen=True)
class TransferRequest:
    host: str
    username: str
    password: str
    local_path: Path


class SettlementTransferService:
    def upload(
        self,
        request: TransferRequest,
    ) -> None:
        connection = FTP_TLS(
            request.host,
        )
        connection.prot_p()  # Secure the data connection
        connection.login(
            request.username,
            request.password,
        )

        with request.local_path.open(
            "rb",
        ) as source:
            connection.storbinary(
                "STOR settlement.csv",
                source,
            )

        connection.quit()
