import regex # Changed from 're' to 'regex' to support timeout

class AuditLogSearch:
    def __init__(self, lines: list[str]) -> None:
        self.lines = lines

    def search(self, request_body: dict[str, str]) -> list[str]:
        expression = request_body["regex"]
        
        # CWE-1333 mitigation: Limit the regular expression execution time.
        # The 'regex' module (a more powerful and compatible replacement for the standard 're' module) 
        # supports a 'timeout' parameter directly in its compile method.
        # This prevents Regular Expression Denial of Service (ReDoS) by ensuring
        # that complex or maliciously crafted regular expressions do not consume 
        # excessive CPU cycles, leading to a denial of service.
        MAX_REGEX_TIMEOUT_SECONDS = 1 
        
        try:
            # Compile the regular expression with a timeout.
            # If compilation or any subsequent search operation using 'compiled' 
            # exceeds the specified timeout, a regex.TimeoutError will be raised.
            compiled = regex.compile(expression, timeout=MAX_REGEX_TIMEOUT_SECONDS)

            matches = []
            for line in self.lines:
                # The timeout set during compile also applies to the search method.
                if compiled.search(line):
                    matches.append(line)

            return matches
        except regex.error as e:
            # Catch general regex errors, which includes syntax errors and timeout errors.
            # regex.TimeoutError is a subclass of regex.error.
            # Providing a specific error message for timeout helps in security monitoring.
            if isinstance(e, regex.TimeoutError):
                raise ValueError(f"Regular expression operation exceeded time limit of {MAX_REGEX_TIMEOUT_SECONDS} seconds.")
            else:
                # Handle other regex-related errors (e.g., malformed patterns) gracefully.
                raise ValueError(f"Invalid regular expression syntax or other regex error: {e}")
