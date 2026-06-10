import os
import subprocess


class VideoTranscoder:
    def transcode(self, source_path: str, output_path: str) -> None:
        ffmpeg_path = os.environ["FFMPEG_PATH"]
        subprocess.run(
            [ffmpeg_path, "-y", "-i", source_path, output_path],
            check=True,
        )


def convert_upload(source_path: str, output_path: str) -> None:
    transcoder = VideoTranscoder()
    transcoder.transcode(source_path, output_path)
