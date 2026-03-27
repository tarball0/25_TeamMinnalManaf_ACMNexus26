from pathlib import Path
import json
from datetime import datetime

from app.image_convertor import bytes_to_grayscale_image
from app.pe_features import extract_pe_features
from app.scorer import compute_suspicion_score
from app.explain import build_explanation

MAX_IMAGE_BYTES = 8 * 1024 * 1024  # use only up to 8 MB for image generation


def analyze_file(file_path: str) -> dict:
    file_path = Path(file_path)
    file_stem = file_path.stem

    image_output = Path("outputs/images") / f"{file_stem}.png"
    report_output = Path("outputs/reports") / f"{file_stem}.json"

    image_info = bytes_to_grayscale_image(
        str(file_path),
        str(image_output),
        max_image_bytes=MAX_IMAGE_BYTES,
    )
    pe_info = extract_pe_features(str(file_path))
    score_info = compute_suspicion_score(pe_info)
    explanation = build_explanation(pe_info, score_info, image_info)

    result = {
        "file_name": file_path.name,
        "timestamp": datetime.now().isoformat(),
        "image_info": image_info,
        "pe_info": pe_info,
        "score_info": score_info,
        "explanation": explanation,
    }

    report_output.parent.mkdir(parents=True, exist_ok=True)
    with open(report_output, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=4)

    return result
