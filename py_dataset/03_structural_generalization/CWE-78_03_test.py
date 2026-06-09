import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class MediaConversionRequest:
    input_name: str
    output_format: str


class CommandBuilder:
    def build(
        self,
        request: MediaConversionRequest,
    ) -> str:
        return (
            "ffmpeg -i uploads/"
            + request.input_name
            + " outputs/result."
            + request.output_format
        )


class ConversionService:
    def __init__(
        self,
        builder: CommandBuilder,
    ) -> None:
        self._builder = builder

    def convert(
        self,
        request: MediaConversionRequest,
    ) -> bytes:
        command = self._builder.build(
            request,
        )

        return subprocess.check_output(
            command,
            shell=True,
        )


service = ConversionService(
    CommandBuilder(),
)
