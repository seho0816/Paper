import json
import sys


class RuntimeOptions:
    debug = False
    payment_validation = True
    allow_guest_checkout = False


class RuntimeOptionUpdater:
    # CWE-15 mitigation: Define a whitelist of allowed configuration options.
    # This prevents an attacker from setting arbitrary attributes on RuntimeOptions
    # or potentially modifying sensitive internal attributes not intended for external control.
    _ALLOWED_OPTIONS = {"debug", "payment_validation", "allow_guest_checkout"}

    def apply(self, payload: dict[str, object]) -> None:
        for option_name, option_value in payload.items():
            # Only set attributes if the option_name is in the approved whitelist.
            if option_name in self._ALLOWED_OPTIONS:
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
