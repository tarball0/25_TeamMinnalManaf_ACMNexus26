from __future__ import annotations

from pathlib import Path
from typing import Any

import numpy as np
from PIL import Image


DEFAULT_WEIGHTS_PATH = Path("app/models/malware_cnn_resnet18.pth")
DEFAULT_IMAGE_SIZE = 224
DEFAULT_MEAN = 0.5
DEFAULT_STD = 0.5
DEFAULT_THRESHOLD = 0.5


def _safe_import_torchvision():
    try:
        import torch
        import torch.nn as nn
        from torchvision import models, transforms
        return torch, nn, models, transforms, None
    except Exception as exc:
        return None, None, None, None, exc


def _grayscale_entropy(gray_array: np.ndarray) -> float:
    if gray_array.size == 0:
        return 0.0

    values = (gray_array * 255.0).clip(0, 255).astype(np.uint8).ravel()
    hist = np.bincount(values, minlength=256).astype(np.float64)
    hist_sum = hist.sum()
    if hist_sum == 0:
        return 0.0

    hist /= hist_sum
    hist = hist[hist > 0]
    return float(-(hist * np.log2(hist)).sum())


def _edge_density(gray_array: np.ndarray) -> float:
    if gray_array.ndim != 2 or gray_array.size == 0:
        return 0.0

    gx = np.abs(np.diff(gray_array, axis=1))
    gy = np.abs(np.diff(gray_array, axis=0))
    gx_mean = float(gx.mean()) if gx.size else 0.0
    gy_mean = float(gy.mean()) if gy.size else 0.0
    return (gx_mean + gy_mean) / 2.0


def _block_variance(gray_array: np.ndarray, block_size: int = 16) -> float:
    if gray_array.ndim != 2 or gray_array.size == 0:
        return 0.0

    height, width = gray_array.shape
    usable_h = (height // block_size) * block_size
    usable_w = (width // block_size) * block_size

    if usable_h == 0 or usable_w == 0:
        return 0.0

    cropped = gray_array[:usable_h, :usable_w]
    blocks = cropped.reshape(
        usable_h // block_size,
        block_size,
        usable_w // block_size,
        block_size,
    ).transpose(0, 2, 1, 3)

    block_means = blocks.mean(axis=(2, 3))
    return float(block_means.var())


def _probability_to_label(prob: float) -> str:
    if prob >= 0.90:
        return "Very likely malware"
    if prob >= 0.75:
        return "Likely malware"
    if prob >= 0.50:
        return "Suspicious / borderline"
    if prob >= 0.25:
        return "Likely benign"
    return "Very likely benign"


def _clean_state_dict(state_dict: dict[str, Any]) -> dict[str, Any]:
    cleaned: dict[str, Any] = {}
    for key, value in state_dict.items():
        new_key = key
        if new_key.startswith("module."):
            new_key = new_key[len("module.") :]
        if new_key.startswith("model."):
            new_key = new_key[len("model.") :]
        cleaned[new_key] = value
    return cleaned


def _create_model(nn, models):
    model = models.resnet18(weights=None)
    model.conv1 = nn.Conv2d(
        in_channels=1,
        out_channels=64,
        kernel_size=7,
        stride=2,
        padding=3,
        bias=False,
    )
    model.fc = nn.Linear(model.fc.in_features, 1)
    return model


def _load_model(weights_path: str | Path | None = None):
    torch, nn, models, transforms, import_error = _safe_import_torchvision()
    if import_error is not None:
        raise RuntimeError(
            "PyTorch/torchvision is not installed. Install torch and torchvision first."
        ) from import_error

    weights_path = Path(weights_path or DEFAULT_WEIGHTS_PATH)
    if not weights_path.exists():
        raise FileNotFoundError(
            f"Malware CNN weights not found at: {weights_path}. "
            "Place your malware-trained checkpoint there."
        )

    checkpoint = torch.load(weights_path, map_location="cpu")
    metadata: dict[str, Any] = {}

    if isinstance(checkpoint, dict):
        state_dict = checkpoint.get("state_dict", checkpoint.get("model_state_dict", checkpoint))
        metadata = checkpoint.get("meta", {}) or {}
        for key in ("threshold", "image_size", "mean", "std", "model_name"):
            if key in checkpoint and key not in metadata:
                metadata[key] = checkpoint[key]
    else:
        state_dict = checkpoint

    if not isinstance(state_dict, dict):
        raise RuntimeError("Checkpoint format is invalid. Expected a state_dict or wrapped checkpoint dict.")

    state_dict = _clean_state_dict(state_dict)

    model = _create_model(nn, models)
    model.load_state_dict(state_dict, strict=True)

    image_size = int(metadata.get("image_size", DEFAULT_IMAGE_SIZE))
    mean = float(metadata.get("mean", DEFAULT_MEAN))
    std = float(metadata.get("std", DEFAULT_STD))
    threshold = float(metadata.get("threshold", DEFAULT_THRESHOLD))
    model_name = str(metadata.get("model_name", "malware_resnet18_grayscale"))

    preprocess = transforms.Compose(
        [
            transforms.Resize((image_size, image_size)),
            transforms.ToTensor(),
            transforms.Normalize(mean=[mean], std=[std]),
        ]
    )

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.eval().to(device)

    return torch, model, preprocess, device, weights_path, model_name, threshold


def analyze_image_with_malware_cnn(
    image_path: str,
    weights_path: str | Path | None = None,
) -> dict[str, Any]:
    try:
        torch, model, preprocess, device, loaded_weights_path, model_name, threshold = _load_model(weights_path)
    except Exception as exc:
        return {
            "available": False,
            "status": "cnn_unavailable",
            "model_name": "malware_resnet18_grayscale",
            "weights": None,
            "pretrained": False,
            "malware_specific": True,
            "malware_probability": None,
            "malware_score": None,
            "visual_score": None,   # backward compatibility
            "visual_label": None,   # backward compatibility
            "threshold": None,
            "confidence": None,
            "image_entropy": None,
            "edge_density": None,
            "block_variance": None,
            "strong_signal_count": 0,
            "reasons": [],
            "error": str(exc),
        }

    try:
        gray_img = Image.open(image_path).convert("L")
    except Exception as exc:
        return {
            "available": False,
            "status": "image_load_failed",
            "model_name": model_name,
            "weights": str(loaded_weights_path),
            "pretrained": True,
            "malware_specific": True,
            "malware_probability": None,
            "malware_score": None,
            "visual_score": None,
            "visual_label": None,
            "threshold": threshold,
            "confidence": None,
            "image_entropy": None,
            "edge_density": None,
            "block_variance": None,
            "strong_signal_count": 0,
            "reasons": [],
            "error": f"Could not load grayscale image: {exc}",
        }

    tensor = preprocess(gray_img).unsqueeze(0).to(device)

    with torch.no_grad():
        logits = model(tensor)
        probability = float(torch.sigmoid(logits).item())

    malware_score = int(round(probability * 100.0))
    confidence = float(abs(probability - 0.5) * 2.0)

    gray_array = np.asarray(gray_img, dtype=np.float32) / 255.0
    image_entropy = _grayscale_entropy(gray_array)
    edge_density = _edge_density(gray_array)
    block_variance = _block_variance(gray_array)

    reasons: list[str] = []
    strong_signal_count = 0

    if probability >= 0.90:
        reasons.append("The malware-trained CNN assigned a very high malware probability.")
        strong_signal_count += 1
    elif probability >= 0.75:
        reasons.append("The malware-trained CNN assigned a high malware probability.")
        strong_signal_count += 1
    elif probability >= 0.50:
        reasons.append("The malware-trained CNN marked the byte image as suspicious.")
    else:
        reasons.append("The malware-trained CNN did not find strong malware evidence in the byte image.")

    if image_entropy >= 7.2:
        reasons.append("The byte image has high entropy, which is common in packed or obfuscated binaries.")
        strong_signal_count += 1
    elif image_entropy >= 6.8:
        reasons.append("The byte image shows mildly elevated entropy.")

    if edge_density >= 0.14:
        reasons.append("The byte image has strong local transitions and fragmented texture.")
        strong_signal_count += 1

    if block_variance >= 0.012:
        reasons.append("The byte image shows noticeable block-to-block variation.")

    return {
        "available": True,
        "status": "ok",
        "model_name": model_name,
        "weights": str(loaded_weights_path),
        "pretrained": True,
        "malware_specific": True,
        "malware_probability": round(probability, 4),
        "malware_score": malware_score,
        "visual_score": malware_score,               # backward compatibility
        "visual_label": _probability_to_label(probability),
        "threshold": round(float(threshold), 4),
        "confidence": round(confidence, 4),
        "image_entropy": round(image_entropy, 4),
        "edge_density": round(edge_density, 4),
        "block_variance": round(block_variance, 4),
        "strong_signal_count": strong_signal_count,
        "reasons": reasons,
        "error": None,
    }
