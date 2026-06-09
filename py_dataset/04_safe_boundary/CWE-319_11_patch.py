from ftplib import FTP_TLS


def upload_report(
    host: str,
    username: str,
    password: str,
    file_path: str,
) -> None:
    ftp = FTP_TLS(host)
    ftp.login(
        username,
        password,
    )
    ftp.prot_p()

    with open(
        file_path,
        "rb",
    ) as source:
        ftp.storbinary(
            "STOR report.csv",
            source,
        )

    ftp.quit()

