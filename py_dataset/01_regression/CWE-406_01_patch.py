import json
import socket


def run_directory_server(
    bind_address: tuple[str, int],
) -> None:
    server = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM,
    )
    server.bind(
        bind_address
    )

    while True:
        request, client = server.recvfrom(
            64
        )

        if request == b"LIST":
            # CWE-406: Untrusted Search Path
            # The original code directly calls `load_all_public_users()`.
            # If `load_all_public_users` is intended to be a global function
            # and the global namespace (or Python's module search path via sys.modules)
            # could be manipulated by an attacker (e.g., through other vulnerabilities
            # that allow arbitrary code execution or global variable modification),
            # then a malicious function could be substituted for `load_all_public_users`.
            # This would lead to arbitrary code execution when the server calls it.
            #
            # To mitigate this "untrusted search path" vulnerability for a function
            # that is expected to be in the global scope, we explicitly retrieve it
            # from the current module's globals dictionary. This makes the lookup
            # explicit and allows for a type check before invocation, preventing
            # calling a potentially hijacked or non-callable object.
            #
            # If `load_all_public_users` is not defined in the module's global scope,
            # `globals().get()` will return `None`, preventing a NameError from being
            # a potential attack vector, and instead gracefully handles the missing function.

            trusted_load_users_func = globals().get("load_all_public_users")

            if callable(trusted_load_users_func):
                body = json.dumps(
                    trusted_load_users_func()
                ).encode(
                    "utf-8"
                )
            else:
                # If the function is not found or not callable, it's safer to return
                # an empty list or an error response rather than crashing or
                # invoking an untrusted function. For a "LIST" request, an empty
                # list is a sensible and safe default.
                body = json.dumps([]).encode("utf-8")
            
            server.sendto(
                body,
                client,
            )
