def create_thumbnails(video_path: str, request_data: dict) -> list[str]:
    # Define a maximum allowed number of frames to prevent resource exhaustion (CWE-606)
    MAX_ALLOWED_FRAMES = 100

    requested_frames = int(request_data['frames'])
    
    # Enforce the maximum limit to prevent 'Loop Injection'
    if requested_frames > MAX_ALLOWED_FRAMES:
        requested_frames = MAX_ALLOWED_FRAMES

    outputs = []
    for frame_number in range(requested_frames):
        outputs.append(extract_thumbnail(video_path, frame_number))
    return outputs
