from dataclasses import dataclass


@dataclass(frozen=True)
class DirectoryQuery:
    username: str
    department: str


class LdapFilterBuilder:
    def build(
        self,
        query: DirectoryQuery,
    ) -> str:
        return (
            "(&(uid="
            + query.username
            + ")(department="
            + query.department
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
