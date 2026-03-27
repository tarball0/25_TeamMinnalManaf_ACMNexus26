from __future__ import annotations

import math
from typing import Any

import numpy as np
from PIL import Image


def _safe_import_torchvision():
    try:
        import torch
        from torchvision import models, transforms
        return torch, models, transforms, None
    except Exception as exc:
        return None, None, None, exc


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


def _label_from_score(score: int) -> str:
    if score >= 70:
        return "Strong visual anomaly"
    if score >= 40:
        return "Moderate visual anomaly"
    return "Low visual anomaly"


def _score_from_metrics(
    image_entropy: float,
    edge_density: float,
    natural_image_confidence: float,
    activation_mean: float,
) -> int:
    entropy_score = np.clip((image_entropy - 6.0) / 2.0, 0.0, 1.0) * 45.0
    edge_score = np.clip((edge_density - 0.05) / 0.20, 0.0, 1.0) * 25.0
    confidence_score = np.clip(1.0 - natural_image_confidence, 0.0, 1.0) * 20.0
    activation_score = np.clip(activation_mean / 1.5, 0.0, 1.0) * 10.0

    total = entropy_score + edge_score + confidence_score + activation_score
    return int(round(min(100.0, total)))


def _build_pretrained_resnet18():
    torch, models, transforms, import_error = _safe_import_torchvision()
    if import_error is not None:
        raise RuntimeError(
            "PyTorch/torchvision is not installed. Install torch and torchvision first."
        ) from import_error

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    try:
        weights_enum = getattr(models, "ResNet18_Weights", None)

        if weights_enum is not None:
            weights = weights_enum.DEFAULT
            model = models.resnet18(weights=weights)
            preprocess = weights.transforms()
            weights_name = str(weights)
        else:
            model = models.resnet18(pretrained=True)
            preprocess = transforms.Compose(
                [
                    transforms.Resize(256),
                    transforms.CenterCrop(224),
                    transforms.ToTensor(),
                    transforms.Normalize(
                        mean=[0.485, 0.456, 0.406],
                        std=[0.229, 0.224, 0.225],
                    ),
                ]
            )
            weights_name = "legacy-imagenet-pretrained"
    except Exception as exc:
        raise RuntimeError(
            "Could not load official pretrained ResNet18 weights. "
            "If this is the first run, connect once to the internet so torchvision can cache them."
        ) from exc

    feature_extractor = torch.nn.Sequential(*list(model.children())[:-1])

    model.eval().to(device)
    feature_extractor.eval().to(device)

    return torch, model, feature_extractor, preprocess, device, weights_name


def analyze_image_with_pretrained_cnn(image_path: str) -> dict[str, Any]:
    try:
        torch, model, feature_extractor, preprocess, device, weights_name = _build_pretrained_resnet18()
    except Exception as exc:
        return {
            "available": False,
            "status": "cnn_unavailable",
            "model_name": "resnet18",
            "weights": None,
            "pretrained": True,
            "malware_specific": False,
            "visual_score": None,
            "visual_label": None,
            "natural_image_confidence": None,
            "image_entropy": None,
            "edge_density": None,
            "activation_mean": None,
            "activation_std": None,
            "reasons": [],
            "error": str(exc),
        }

    try:
        gray_img = Image.open(image_path).convert("L")
        rgb_img = gray_img.convert("RGB")
    except Exception as exc:
        return {
            "available": False,
            "status": "image_load_failed",
            "model_name": "resnet18",
            "weights": weights_name,
            "pretrained": True,
            "malware_specific": False,
            "visual_score": None,
            "visual_label": None,
            "natural_image_confidence": None,
            "image_entropy": None,
            "edge_density": None,
            "activation_mean": None,
            "activation_std": None,
            "reasons": [],
            "error": f"Could not load grayscale image: {exc}",
        }

    tensor = preprocess(rgb_img).unsqueeze(0).to(device)

    with torch.no_grad():
        logits = model(tensor)
        probs = torch.softmax(logits, dim=1)
        top_prob, _ = probs.max(dim=1)

        embedding = feature_extractor(tensor).flatten(1)

    gray_array = np.asarray(gray_img, dtype=np.float32) / 255.0

    image_entropy = _grayscale_entropy(gray_array)
    edge_density = _edge_density(gray_array)
    natural_image_confidence = float(top_prob.item())
    activation_mean = float(embedding.abs().mean().item())
    activation_std = float(embedding.std().item())

    visual_score = _score_from_metrics(
        image_entropy=image_entropy,
        edge_density=edge_density,
        natural_image_confidence=natural_image_confidence,
        activation_mean=activation_mean,
    )

    reasons: list[str] = []

    if image_entropy >= 7.0:
        reasons.append("The byte image has high grayscale entropy, which is common in packed or compressed binaries.")
    elif image_entropy >= 6.5:
        reasons.append("The byte image has moderately high grayscale entropy.")

    if edge_density >= 0.12:
        reasons.append("The byte image shows abrupt texture transitions and dense local changes.")
    elif edge_density >= 0.08:
        reasons.append("The byte image has moderate edge density.")

    if natural_image_confidence <= 0.15:
        reasons.append("The pretrained natural-image CNN is not confident on this texture, suggesting it is far from ordinary image structure.")

    if activation_mean >= 1.0:
        reasons.append("Deep CNN feature activations are relatively strong for this byte-image pattern.")

    if not reasons:
        reasons.append("The pretrained CNN did not detect a strong visual anomaly in the grayscale byte image.")

    return {
        "available": True,
        "status": "ok",
        "model_name": "resnet18",
        "weights": weights_name,
        "pretrained": True,
        "malware_specific": False,
        "visual_score": visual_score,
        "visual_label": _label_from_score(visual_score),
        "natural_image_confidence": round(natural_image_confidence, 4),
        "image_entropy": round(image_entropy, 4),
        "edge_density": round(edge_density, 4),
        "activation_mean": round(activation_mean, 4),
        "activation_std": round(activation_std, 4),
        "reasons": reasons,
        "error": None,
    }
