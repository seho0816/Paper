class ProxyHeaderParser:
    def parse(
        self,
        lines: list[bytes],
    ) -> dict[bytes, bytes]:
        parsed = {}
        
        # Store these specially to apply RFC rules after parsing all lines
        transfer_encoding_header_value: bytes | None = None
        content_length_values: list[bytes] = []

        for line in lines:
            try:
                name, value = line.split(b":", 1)
            except ValueError:
                # If a line does not contain a colon, the original code would raise a ValueError.
                # Maintaining this behavior, as CWE-444 focuses on ambiguous interpretation,
                # not on handling fundamentally malformed lines that cause parsing errors.
                raise

            header_name = name.strip().lower()
            header_value = value.strip()

            if header_name == b"transfer-encoding":
                # RFC 7230, Section 3.3.1 states: "A sender MUST NOT generate multiple
                # Transfer-Encoding header fields in a message." If multiple are received,
                # they are technically malformed. To maintain consistency with how the original
                # parser handles general duplicate headers (last one wins), we store the last encountered value.
                transfer_encoding_header_value = header_value
            elif header_name == b"content-length":
                # Collect all Content-Length values to check for duplicates and conflicts later.
                content_length_values.append(header_value)
            else:
                # For all other headers, maintain the original behavior: the last value wins if duplicated.
                parsed[header_name] = header_value

        # --- Apply RFC 7230 rules for Content-Length and Transfer-Encoding to prevent CWE-444 (HTTP Desync) ---

        # 1. Prioritize Transfer-Encoding over Content-Length
        if transfer_encoding_header_value is not None:
            # If Transfer-Encoding header was present, add it to the parsed dict.
            parsed[b"transfer-encoding"] = transfer_encoding_header_value
            
            # RFC 7230, Section 3.3.3 states: "If a message is received with both a
            # Transfer-Encoding and a Content-Length header field, the Content-Length
            # header field MUST be ignored."
            # By not processing `content_length_values` in this branch, Content-Length
            # is effectively ignored and not added to the `parsed` dictionary.
        else:
            # 2. Handle Content-Length only if Transfer-Encoding is NOT present
            if content_length_values:
                # RFC 7230, Section 3.3.2 states: "A sender MUST NOT generate multiple
                # Content-Length header fields in a message. If a message is received
                # with multiple Content-Length header fields having different field-values,
                # then the message is malformed; a proxy MUST either forward such a message
                # without a Content-Length header field or respond with a 400 (Bad Request) status code."

                # Check if all collected Content-Length values are identical.
                if len(set(content_length_values)) > 1:
                    # Malformed: multiple Content-Length headers with different values.
                    # As a proxy, we must remove the Content-Length header to prevent desync.
                    # By doing nothing here, content-length will not be added to `parsed`.
                    pass
                else:
                    # Only one Content-Length value, or multiple identical ones.
                    # It's safe to use this value. Use the first one encountered.
                    parsed[b"content-length"] = content_length_values[0]

        return parsed


def send_backend_request(
    request_line: bytes,
    headers: dict[bytes, bytes],
    body: bytes,
) -> None:
    # This function is a placeholder and its implementation is not relevant
    # to the CWE-444 vulnerability or its fix in the ProxyHeaderParser.
    pass


class RequestProxy:
    def __init__(
        self,
        parser: ProxyHeaderParser,
    ) -> None:
        self._parser = parser

    def forward(
        self,
        request_line: bytes,
        header_lines: list[bytes],
        body: bytes,
    ) -> None:
        headers = self._parser.parse(
            header_lines
        )
        send_backend_request(
            request_line,
            headers,
            body,
        )
