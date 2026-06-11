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
    ) -> list[str]:  # Changed return type hint to list[str]
        # Construct the command as a list of arguments to prevent shell interpretation
        return [
            "ffmpeg",
            "-i",
            "uploads/" + request.input_name,
            "outputs/result." + request.output_format,
        ]


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
        command_args = self._builder.build(  # Get the command as a list of arguments
            request,
        )

        return subprocess.check_output(
            command_args,  # Pass the command as a list of arguments
            shell=False,  # Explicitly set shell=False to prevent command injection
        )


service = ConversionService(
    CommandBuilder(),
)
