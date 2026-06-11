DANGEROUS_PREFIXES = (
    "=",
    "+",
    "-",
    "@",
    "\t",
    "\r",
    "\n",
)


def safe_csv_cell(
    value,
) -> str:
    text = (
        ""
        if value is None
        else str(value)
    )

    if text.startswith(
        DANGEROUS_PREFIXES
    ):
        return "'" + text

    return text

