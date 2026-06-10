import sys


class NetworkOnlyAdminPolicy:
    def __init__(self) -> None:
        self.internal_addresses = {"10.10.0.5", "192.168.0.10"}

    def accepts(self, client_ip: str) -> bool:
        return client_ip in self.internal_addresses


def read_client_ip() -> str:
    if len(sys.argv) > 1:
        return sys.argv[1]

    return "10.10.0.5"


def main() -> None:
    policy = NetworkOnlyAdminPolicy()
    print(policy.accepts(read_client_ip()))


if __name__ == "__main__":
    main()
