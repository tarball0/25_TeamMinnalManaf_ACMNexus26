from pathlib import Path
import json
import hashlib
import re
from datetime import datetime

from .image_convertor import bytes_to_grayscale_image
from .pe_features import extract_pe_features
from .scorer import compute_suspicion_score
from .explain import build_explanation
from .cnn_model import analyze_image_with_malware_cnn

BASE_DIR = Path(__file__).resolve().parents[1]
MAX_IMAGE_BYTES = 8 * 1024 * 1024


def _safe_name(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._")
    return cleaned or "file"


def _unique_output_id(file_path: Path) -> str:
    stat = file_path.stat()
    raw = f"{file_path.resolve()}|{stat.st_size}|{stat.st_mtime_ns}"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:10]
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{_safe_name(file_path.stem)}_{stamp}_{digest}"


def analyze_file(file_path: str) -> dict:
    file_path = Path(file_path).resolve()
    output_id = _unique_output_id(file_path)

    image_output = BASE_DIR / "outputs" / "images" / f"{output_id}.png"
    report_output = BASE_DIR / "outputs" / "reports" / f"{output_id}.json"

    image_info = bytes_to_grayscale_image(
        str(file_path),
        str(image_output),
        max_image_bytes=MAX_IMAGE_BYTES,
    )

    pe_info = extract_pe_features(str(file_path))
    cnn_info = analyze_image_with_malware_cnn(image_info["image_path"])
    score_info = compute_suspicion_score(pe_info, cnn_info)
    explanation = build_explanation(pe_info, score_info, image_info, cnn_info)

    result = {
        "file_name": file_path.name,
        "timestamp": datetime.now().isoformat(),
        "image_info": image_info,
        "pe_info": pe_info,
        "cnn_info": cnn_info,
        "score_info": score_info,
        "explanation": explanation,
    }

    report_output.parent.mkdir(parents=True, exist_ok=True)
    with open(report_output, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=4)

    return result
