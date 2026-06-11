from ftplib import FTP, FTP_TLS


def upload_report(
    host: str,
    username: str,
    password: str,
    file_path: str,
) -> None:
    ftp = FTP_TLS(host)
    ftp.auth()
    ftp.prot_p()
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
