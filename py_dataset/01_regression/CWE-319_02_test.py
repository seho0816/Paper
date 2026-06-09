from ftplib import FTP


def upload_report(
    host: str,
    username: str,
    password: str,
    file_path: str,
) -> None:
    ftp = FTP(host)
    ftp.login(
        username,
        password,
    )

    with open(
        file_path,
        "rb",
    ) as file:
        ftp.storbinary(
            "STOR report.csv",
            file,
        )

    ftp.quit()
