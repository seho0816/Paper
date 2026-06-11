from dataclasses import dataclass


# DIRECTORY_BASE is assumed to be an existing constant in the application
# For syntactic completeness and to ensure the provided code runs, a placeholder value is defined.
# This constant is not related to the CWE-90 fix itself.
DIRECTORY_BASE = "dc=example,dc=com"


@dataclass(frozen=True)
class DirectoryQuery:
    username: str
    department: str


class LdapFilterBuilder:
    def _escape_ldap_filter_value(self, value: str) -> str:
        """
        Escapes special characters in a string for use in an LDAP filter value,
        preventing LDAP injection (CWE-90).
        Characters that must be escaped according to RFC 4515 are:
        '*', '(', ')', '\', and NUL (U+0000).
        Also, any character with a code point less than 0x20 (ASCII control characters)
        should be escaped.
        """
        escaped_value = []
        for char in value:
            char_code = ord(char)
            if char == '*':
                escaped_value.append('\\2a')
            elif char == '(':
                escaped_value.append('\\28')
            elif char == ')':
                escaped_value.append('\\29')
            elif char == '\\':
                escaped_value.append('\\5c')
            elif char_code < 0x20:  # Control characters (including NUL U+0000)
                escaped_value.append(f'\\{char_code:02x}')
            else:
                escaped_value.append(char)
        return "".join(escaped_value)

    def build(
        self,
        query: DirectoryQuery,
    ) -> str:
        # Escape user-controlled input to prevent LDAP injection
        escaped_username = self._escape_ldap_filter_value(query.username)
        escaped_department = self._escape_ldap_filter_value(query.department)

        return (
            "(&(uid="
            + escaped_username
            + ")(department="
            + escaped_department
            + "))"
        )


class DirectoryRepository:
    def __init__(
        self,
        connection,
        builder: LdapFilterBuilder,
    ) -> None:
        self._connection = connection
        self._builder = builder

    def search(
        self,
        query: DirectoryQuery,
    ) -> list:
        ldap_filter = self._builder.build(
            query
        )
        self._connection.search(
            DIRECTORY_BASE,
            ldap_filter,
        )

        return list(
            self._connection.entries
        )
