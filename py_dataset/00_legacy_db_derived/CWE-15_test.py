import json
import sys


class RuntimeOptions:
    debug = False
    payment_validation = True
    allow_guest_checkout = False


class RuntimeOptionUpdater:
    def apply(self, payload: dict[str, object]) -> None:
        for option_name, option_value in payload.items():
            setattr(RuntimeOptions, option_name, option_value)


def read_payload() -> dict[str, object]:
    if len(sys.argv) > 1:
        return json.loads(sys.argv[1])

    return {
        "debug": True,
        "payment_validation": False,
    }


def main() -> None:
    updater = RuntimeOptionUpdater()
    updater.apply(read_payload())
    print(RuntimeOptions.debug, RuntimeOptions.payment_validation)


if __name__ == "__main__":
    main()
