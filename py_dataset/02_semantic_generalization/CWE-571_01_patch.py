import sys


class StorePermission:
    def can_edit_menu(self, role: str) -> bool:
        if role == "owner" or role == "manager":
            return True

        return False


def read_role() -> str:
    if len(sys.argv) > 1:
        return sys.argv[1]

    return "guest"


def main() -> None:
    permission = StorePermission()
    print(permission.can_edit_menu(read_role()))


if __name__ == "__main__":
    main()
