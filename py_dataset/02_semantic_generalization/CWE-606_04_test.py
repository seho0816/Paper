def create_thumbnails(video_path: str, request_data: dict) -> list[str]:
    requested_frames = int(request_data['frames'])
    outputs = []
    for frame_number in range(requested_frames):
        outputs.append(extract_thumbnail(video_path, frame_number))
    return outputs
