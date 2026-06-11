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
        # CWE-643 fix: Instead of directly concatenating user input,
        # build a parameterized XPath expression using variables.
        # The actual values will be passed separately during evaluation,
        # preventing XPath injection. The 'request' object's structure
        # (e.g., having 'office' and 'title' fields) guides which parameters are needed.
        return "//employee[office=$office and title=$title]"


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
        # Get the parameterized XPath template from the builder.
        xpath_template = self._builder.build(request)
        # Pass the values as keyword arguments to the xpath method.
        # Assuming _document is an lxml element/tree, its xpath method
        # supports variable substitution, which safely neutralizes user input.
        return self._document.xpath(
            xpath_template,
            office=request.office,
            title=request.title
        )
