from pathlib import Path
import math

import numpy as np
from PIL import Image

DEFAULT_MAX_IMAGE_BYTES = 8 * 1024 * 1024  # 8 MB sampled for image generation
READ_CHUNK_SIZE = 4 * 1024 * 1024          # 4 MB read chunks


def choose_width(file_size: int) -> int:
    if file_size < 10_000:
        return 32
    if file_size < 30_000:
        return 64
    if file_size < 100_000:
        return 128
    if file_size < 500_000:
        return 256
    if file_size < 1_000_000:
        return 512
    if file_size < 10_000_000:
        return 1024
    return 2048


def _sample_bytes_streaming(file_path: Path, max_bytes: int) -> tuple[bytes, int]:
    """
    If file is small, read all bytes.
    If file is large, sample bytes while streaming from disk.
    Returns: (sampled_bytes, stride)
    """
    file_size = file_path.stat().st_size

    if file_size == 0:
        raise ValueError("File is empty.")

    if file_size <= max_bytes:
        return file_path.read_bytes(), 1

    stride = math.ceil(file_size / max_bytes)
    sampled_parts = []
    offset = 0

    with file_path.open("rb") as f:
        while True:
            chunk = f.read(READ_CHUNK_SIZE)
            if not chunk:
                break

            arr = np.frombuffer(chunk, dtype=np.uint8)

            start = (-offset) % stride
            picked = arr[start::stride]
            if picked.size:
                sampled_parts.append(picked)

            offset += len(arr)

    if not sampled_parts:
        return b"", stride

    sampled = np.concatenate(sampled_parts)
    if sampled.size > max_bytes:
        sampled = sampled[:max_bytes]

    return sampled.tobytes(), stride


def bytes_to_grayscale_image(
    file_path: str,
    output_path: str,
    max_image_bytes: int = DEFAULT_MAX_IMAGE_BYTES,
) -> dict:
    path = Path(file_path)
    file_size = path.stat().st_size

    sampled_data, stride = _sample_bytes_streaming(path, max_image_bytes)

    if not sampled_data:
        raise ValueError("Could not generate grayscale bytes.")

    arr = np.frombuffer(sampled_data, dtype=np.uint8)
    width = choose_width(len(arr))
    height = math.ceil(len(arr) / width)

    padded_len = width * height
    if padded_len > len(arr):
        arr = np.pad(arr, (0, padded_len - len(arr)), mode="constant", constant_values=0)

    img_array = arr.reshape((height, width))
    image = Image.fromarray(img_array, mode="L")

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    image.save(output)

    return {
        "image_path": str(output),
        "width": width,
        "height": height,
        "file_size_bytes": file_size,
        "image_source_bytes": int(len(sampled_data)),
        "sampling_stride": int(stride),
        "sampled_for_image": bool(file_size > len(sampled_data)),
    }
