from dataclasses import dataclass
from urllib.parse import unquote


@dataclass(frozen=True)
class EncodedName:
    raw_value: str


class NameDecoder:
    def decode(
        self,
        value: str,
    ) -> str:
        return unquote(
            value
        )


class FileNameService:
    def __init__(
        self,
        decoder: NameDecoder,
    ) -> None:
        self._decoder = decoder

    def normalize(
        self,
        request: EncodedName,
    ) -> str:
        # Perform the first decoding
        first_decoded = self._decoder.decode(
            request.raw_value
        )

        # Perform the second decoding as per the original code's logic.
        # This consecutive decoding is what makes the check vulnerable if not handled correctly.
        final_decoded = self._decoder.decode(
            first_decoded
        )

        # The vulnerability (CWE-174) was that the check for ".." was performed after
        # the first decode but before the second, allowing bypass via double-encoding.
        # Now, the check is performed on the fully decoded string.
        if ".." in final_decoded:
            raise ValueError(
                "invalid file name"
            )

        return final_decoded
