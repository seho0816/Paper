from dataclasses import dataclass


@dataclass(frozen=True)
class EmployeeQuery:
    office: str
    title: str


class XPathBuilder:
    def build(
        self,
        request: EmployeeQuery,
    ) -> str:
        return (
            "//employee[office='"
            + request.office
            + "' and title='"
            + request.title
            + "']"
        )


class EmployeeXmlRepository:
    def __init__(
        self,
        document,
        builder: XPathBuilder,
    ) -> None:
        self._document = document
        self._builder = builder

    def search(
        self,
        request: EmployeeQuery,
    ) -> list:
        return self._document.xpath(
            self._builder.build(
                request
            )
        )
