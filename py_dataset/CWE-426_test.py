import subprocess


class VideoTranscoder:
    def transcode(self, source_path: str, output_path: str) -> None:
        subprocess.run(
            ["ffmpeg", "-y", "-i", source_path, output_path],
            check=True,
        )


def convert_upload(source_path: str, output_path: str) -> None:
    transcoder = VideoTranscoder()
    transcoder.transcode(source_path, output_path)
