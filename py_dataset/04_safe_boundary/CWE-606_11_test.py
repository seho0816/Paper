RENDER_PRESETS = {
    'quick': 1,
    'standard': 3,
    'detailed': 5,
}

def render_preview(payload: dict) -> list[bytes]:
    count = RENDER_PRESETS.get(payload.get('quality'))
    if count is None:
        raise ValueError('unsupported quality')
    return [render_frame(index) for index in range(count)]
