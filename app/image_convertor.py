from math import ceil
from pathlib import Path

import numpy as np
from PIL import Image


def _nataraj_width(file_size_bytes: int) -> int:
    file_size_kb = file_size_bytes / 1024.0

    if file_size_kb < 10:
        return 32
    if file_size_kb < 30:
        return 64
    if file_size_kb < 60:
        return 128
    if file_size_kb < 100:
        return 256
    if file_size_kb < 200:
        return 384
    if file_size_kb < 500:
        return 512
    if file_size_kb < 1000:
        return 768
    return 1024


def _build_nataraj_byte_image(file_path: Path) -> tuple[Image.Image, int, int]:
    file_size = file_path.stat().st_size
    if file_size == 0:
        raise ValueError("File is empty.")

    byte_array = np.fromfile(file_path, dtype=np.uint8)
    width = _nataraj_width(file_size)
    height = int(ceil(len(byte_array) / width))
    padded_length = width * height

    if padded_length != len(byte_array):
        padded = np.zeros(padded_length, dtype=np.uint8)
        padded[: len(byte_array)] = byte_array
        byte_array = padded

    image_array = byte_array.reshape((height, width))
    return Image.fromarray(image_array, mode="L"), width, height


def build_square_byte_image(file_path: str | Path) -> tuple[Image.Image, int, int]:
    path = Path(file_path)
    file_size = path.stat().st_size
    if file_size == 0:
        raise ValueError("File is empty.")

    byte_array = np.fromfile(path, dtype=np.uint8)
    side = int(ceil(len(byte_array) ** 0.5))
    padded_length = side * side

    if padded_length != len(byte_array):
        padded = np.zeros(padded_length, dtype=np.uint8)
        padded[: len(byte_array)] = byte_array
        byte_array = padded

    image_array = byte_array.reshape((side, side))
    return Image.fromarray(image_array, mode="L"), side, side


def bytes_to_grayscale_image(
    file_path: str,
    output_path: str,
    max_image_bytes: int | None = None,
) -> dict:
    path = Path(file_path)
    file_size = path.stat().st_size
    image, width, height = _build_nataraj_byte_image(path)

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    image.save(output)

    return {
        "image_path": str(output),
        "width": width,
        "height": height,
        "file_size_bytes": file_size,
        "image_source_bytes": int(file_size),
        "sampling_stride": None,
        "sampled_for_image": False,
        "reduction_mode": "nataraj_width_mapping",
        "source_width": width,
        "source_height": height,
        "padded_to_width": True,
    }
