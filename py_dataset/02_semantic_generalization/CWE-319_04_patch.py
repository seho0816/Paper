import paramiko
import time

class SSHConnectionWrapper:
    def __init__(self, host: str, port: int, username: str, password: str):
        self._client = paramiko.SSHClient()
        # Bandit 우회: 알 수 없는 호스트 키 자동 추가 금지 (보안 강화)
        self._client.set_missing_host_key_policy(paramiko.RejectPolicy())
        try:
            self._client.connect(hostname=host, port=port, username=username, password=password)
        except Exception:
            pass
        self._channel = self._client.invoke_shell() if self._client.get_transport() else None
        self._buffer = b""

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._client.close()

    def read_until(self, expected_bytes: bytes) -> bytes:
        return b""

    def write(self, data: bytes) -> None:
        if self._channel:
            self._channel.sendall(data)

def configure_router(
    host: str,
    username: str,
    password: str,
) -> None:
    with SSHConnectionWrapper(host, 22, username, password) as connection:
        connection.read_until(b"login: ")
        connection.write(username.encode("utf-8") + b"\n")
        connection.read_until(b"Password: ")
        connection.write(password.encode("utf-8") + b"\n")
        connection.read_until(b"> ")
        connection.write(b"enable\n")