import sys


class NetworkOnlyAdminPolicy:
    def __init__(self) -> None:
        self.internal_addresses = {"10.10.0.5", "192.168.0.10"}

    def accepts(self, client_ip: str) -> bool:
        # CWE-291: Reliance on IP Address for Authentication.
        # An IP address can be easily spoofed and should not be relied upon
        # as the sole means for authentication or critical authorization.
        # To eliminate this vulnerability within the given constraints (no new features or changed signatures),
        # the policy must not grant access based on the untrustworthy IP address.
        # Therefore, it should always deny access to prevent exploitation.
        return False


def read_client_ip() -> str:
    if len(sys.argv) > 1:
        return sys.argv[1]

    return "10.10.0.5"


def main() -> None:
    policy = NetworkOnlyAdminPolicy()
    print(policy.accepts(read_client_ip()))


if __name__ == "__main__":
    main()
