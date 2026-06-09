from dataclasses import dataclass
from ftplib import FTP
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
        connection = FTP(
            request.host,
        )
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
