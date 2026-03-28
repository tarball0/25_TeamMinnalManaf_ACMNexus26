from __future__ import annotations

from pathlib import Path
from typing import Any

import numpy as np
from PIL import Image

CUSTOM_MODEL_PATH = Path(__file__).resolve().parent / "models" / "binary_malware_scanner.pth"
INPUT_SIZE = 224
NUM_CLASSES = 1
IMAGENET_MEAN = [0.485, 0.456, 0.406]
IMAGENET_STD = [0.229, 0.224, 0.225]


def _safe_import_torchvision():
    try:
        import torch
        from torchvision import models, transforms

        return torch, models, transforms, None
    except Exception as exc:
        return None, None, None, exc


def _clean_state_dict(state_dict: dict[str, Any]) -> dict[str, Any]:
    cleaned: dict[str, Any] = {}
    for key, value in state_dict.items():
        if key.startswith("module."):
            key = key[len("module.") :]
        cleaned[key] = value
    return cleaned


def _grayscale_entropy(gray_array: np.ndarray) -> float:
    if gray_array.size == 0:
        return 0.0

    values = (gray_array * 255.0).clip(0, 255).astype(np.uint8).ravel()
    hist = np.bincount(values, minlength=256).astype(np.float64)
    total = hist.sum()

    if total == 0:
        return 0.0

    hist /= total
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


def _scaled_score(value: float, low: float, high: float) -> float:
    if high <= low:
        return 0.0
    if value <= low:
        return 0.0
    if value >= high:
        return 100.0
    return 100.0 * (value - low) / (high - low)


def _visual_label(score: int) -> str:
    if score >= 80:
        return "Strong malware evidence"
    if score >= 60:
        return "Moderate malware evidence"
    if score >= 40:
        return "Weak malware evidence"
    return "Low CNN evidence"


def _binary_margin(probability: float) -> float:
    return abs((2.0 * probability) - 1.0)


def _tiny_image_penalty(width: int, height: int) -> float:
    area = width * height
    if area >= 4096:
        return 1.0
    if area <= 1024:
        return 0.35
    return 0.35 + (0.65 * ((area - 1024) / (4096 - 1024)))


def _entropy_penalty(image_entropy: float) -> float:
    if image_entropy >= 6.0:
        return 1.0
    if image_entropy <= 2.5:
        return 0.4
    return 0.4 + (0.6 * ((image_entropy - 2.5) / (6.0 - 2.5)))


def _calibrate_probability(
    malware_probability: float,
    image_entropy: float,
    width: int,
    height: int,
) -> tuple[float, float]:
    reliability = _tiny_image_penalty(width, height) * _entropy_penalty(image_entropy)

    if malware_probability >= 0.5:
        adjusted = 0.5 + ((malware_probability - 0.5) * reliability)
    else:
        adjusted = malware_probability

    return adjusted, reliability


def _build_custom_model(torch, models, transforms, weights_path: str | Path | None = None):
    resolved_weights = Path(weights_path or CUSTOM_MODEL_PATH)
    if not resolved_weights.exists():
        raise FileNotFoundError(f"Missing EfficientNet malware weights: {resolved_weights}")

    model = models.efficientnet_b0(weights=None)
    in_features = model.classifier[1].in_features
    model.classifier[1] = torch.nn.Linear(in_features, NUM_CLASSES)

    checkpoint = torch.load(resolved_weights, map_location="cpu")
    if isinstance(checkpoint, dict) and "state_dict" in checkpoint:
        state_dict = checkpoint["state_dict"]
    else:
        state_dict = checkpoint

    if not isinstance(state_dict, dict):
        raise RuntimeError("Checkpoint format is not a valid PyTorch state_dict.")

    cleaned_state_dict = _clean_state_dict(state_dict)
    model.load_state_dict(cleaned_state_dict, strict=True)

    weights_enum = getattr(models, "EfficientNet_B0_Weights", None)
    preprocess = transforms.Compose(
        [
            transforms.Resize((INPUT_SIZE, INPUT_SIZE)),
            transforms.Grayscale(num_output_channels=3),
            transforms.ToTensor(),
            transforms.Normalize(
                mean=IMAGENET_MEAN,
                std=IMAGENET_STD,
            ),
        ]
    )
    if weights_enum is not None:
        weights = weights_enum.DEFAULT
        weights_name = f"fine-tuned-from-{weights}"
    else:
        weights_name = "fine-tuned-from-imagenet-defaults"

    return model, preprocess, {
        "mode": "custom",
        "model_name": "efficientnet-b0",
        "weights": str(resolved_weights),
        "weights_name": weights_name,
        "pretrained": True,
        "malware_specific": True,
        "input_mode": "rgb",
        "input_size": INPUT_SIZE,
    }


def _build_pretrained_resnet18(torch, models, transforms):
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
                    mean=IMAGENET_MEAN,
                    std=IMAGENET_STD,
                ),
            ]
        )
        weights_name = "legacy-imagenet-pretrained"

    feature_extractor = torch.nn.Sequential(*list(model.children())[:-1])
    return feature_extractor, preprocess, {
        "mode": "fallback",
        "model_name": "resnet18",
        "weights": weights_name,
        "pretrained": True,
        "malware_specific": False,
        "input_mode": "rgb",
        "input_size": 224,
    }


def _load_model(weights_path: str | Path | None = None):
    torch, models, transforms, import_error = _safe_import_torchvision()
    if import_error is not None:
        raise RuntimeError(
            "PyTorch and torchvision are required. Install torch and torchvision first."
        ) from import_error

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    custom_error = None
    try:
        model, preprocess, metadata = _build_custom_model(torch, models, transforms, weights_path)
    except Exception as exc:
        custom_error = exc
        try:
            model, preprocess, metadata = _build_pretrained_resnet18(torch, models, transforms)
        except Exception as fallback_exc:
            raise RuntimeError(
                f"EfficientNet malware CNN unavailable ({custom_error}). "
                "Fallback ResNet18 could not be loaded either. "
                "If this is the first run, connect once to the internet so torchvision can cache the pretrained weights."
            ) from fallback_exc

    model.eval().to(device)
    return torch, model, preprocess, device, metadata, custom_error


def _analyze_loaded_image(
    gray_img: Image.Image,
    torch,
    model,
    preprocess,
    device,
    metadata: dict[str, Any],
    expected_weights: str,
    custom_error: Exception | None,
    variant_name: str,
) -> dict[str, Any]:
    width, height = gray_img.size
    model_input_image = gray_img
    tensor = preprocess(model_input_image).unsqueeze(0).to(device)

    with torch.no_grad():
        outputs = model(tensor)

    gray_array = np.asarray(gray_img, dtype=np.float32) / 255.0
    image_entropy = _grayscale_entropy(gray_array)
    edge_density = _edge_density(gray_array)
    block_variance = _block_variance(gray_array)

    reasons: list[str] = []
    strong_signal_count = 0
    activation_mean = None
    activation_std = None
    calibration_reasons: list[str] = []
    calibration_reliability = 1.0

    if metadata["mode"] == "custom":
        logit = float(outputs.reshape(-1)[0].detach().cpu().item())
        raw_malware_probability = float(torch.sigmoid(outputs.reshape(-1))[0].detach().cpu().item())
        malware_probability, calibration_reliability = _calibrate_probability(
            raw_malware_probability,
            image_entropy,
            width,
            height,
        )
        benign_probability = max(0.0, 1.0 - malware_probability)
        top1_idx = 0 if malware_probability >= benign_probability else 1
        top1_conf = max(malware_probability, benign_probability)
        top2_conf = min(malware_probability, benign_probability)
        top_margin = abs(malware_probability - benign_probability)
        visual_score = int(round(malware_probability * 100.0))

        if calibration_reliability < 0.99:
            if (width * height) < 4096:
                calibration_reasons.append(
                    "CNN confidence was reduced because the byte image is very small and had to be upscaled heavily."
                )
            if image_entropy < 6.0:
                calibration_reasons.append(
                    "CNN confidence was reduced because the byte image has limited entropy and provides weaker visual signal."
                )

        entropy_score = _scaled_score(image_entropy, 6.8, 7.5)
        edge_score = _scaled_score(edge_density, 0.10, 0.22)
        variance_score = _scaled_score(block_variance, 0.010, 0.030)

        if malware_probability >= 0.90:
            reasons.append("EfficientNet-B0 found a very strong malware probability on the byte image.")
            strong_signal_count += 1
        elif malware_probability >= 0.75:
            reasons.append("EfficientNet-B0 found a clear malware-like visual pattern.")
            strong_signal_count += 1
        elif malware_probability >= 0.55:
            reasons.append("EfficientNet-B0 found a moderate malware-like visual pattern.")
        else:
            reasons.append("EfficientNet-B0 leaned benign on the byte image.")

        if top_margin >= 0.50:
            reasons.append("The binary decision margin was strong, so the safe-versus-malware decision was decisive.")
            strong_signal_count += 1
        elif top_margin >= 0.20:
            reasons.append("The binary decision margin was moderate.")

        if entropy_score >= 70:
            reasons.append("The byte image also has high entropy, which often appears in packed binaries.")
        if edge_score >= 70:
            reasons.append("The byte image has dense local transitions.")
        if variance_score >= 60:
            reasons.append("The byte image shows notable block-to-block variation.")

        reasons.extend(calibration_reasons)
        natural_image_confidence = benign_probability
    else:
        logit = None
        raw_malware_probability = None
        embedding = outputs.flatten(1)
        activation_mean = float(embedding.abs().mean().item())
        activation_std = float(embedding.std().item())

        entropy_score = _scaled_score(image_entropy, 6.8, 7.4)
        edge_score = _scaled_score(edge_density, 0.10, 0.22)
        variance_score = _scaled_score(block_variance, 0.012, 0.03)
        activation_score = _scaled_score(activation_std, 0.95, 1.4)

        visual_score = int(
            round(
                min(
                    100.0,
                    (0.40 * entropy_score)
                    + (0.30 * edge_score)
                    + (0.20 * variance_score)
                    + (0.10 * activation_score),
                )
            )
        )

        malware_probability = round(visual_score / 100.0, 4)
        benign_probability = round(max(0.0, 1.0 - malware_probability), 4)
        top1_idx = None
        top1_conf = malware_probability
        top2_conf = benign_probability
        top_margin = round(max(0.0, malware_probability - 0.5), 4)
        natural_image_confidence = benign_probability

        if image_entropy >= 7.3:
            reasons.append("The byte image has high grayscale entropy, which is common in packed or compressed binaries.")
            strong_signal_count += 1
        elif image_entropy >= 7.0:
            reasons.append("The byte image has elevated grayscale entropy.")

        if edge_density >= 0.18:
            reasons.append("The byte image shows abrupt texture transitions and dense local changes.")
            strong_signal_count += 1
        elif edge_density >= 0.14:
            reasons.append("The byte image shows moderate local transitions.")

        if block_variance >= 0.020:
            reasons.append("The byte image shows strong block-to-block variation.")
            strong_signal_count += 1
        elif block_variance >= 0.012:
            reasons.append("The byte image shows noticeable block-to-block variation.")

        if activation_std >= 1.20:
            reasons.append("The pretrained visual encoder produced unusually dispersed deep features for this byte image.")

    if not reasons:
        reasons.append("The CNN did not find a strong visual anomaly in the byte image.")

    return {
        "available": True,
        "status": "ok",
        "mode": metadata["mode"],
        "model_name": metadata["model_name"],
        "weights": metadata["weights"],
        "expected_weights": expected_weights,
        "pretrained": metadata["pretrained"],
        "malware_specific": metadata["malware_specific"],
        "binary_calibrated": metadata["malware_specific"],
        "input_mode": metadata.get("input_mode"),
        "input_size": metadata.get("input_size"),
        "variant_name": variant_name,
        "source_width": width,
        "source_height": height,
        "source_area": width * height,
        "calibration_reliability": round(calibration_reliability, 4),
        "raw_malware_probability": round(raw_malware_probability, 4) if raw_malware_probability is not None else None,
        "visual_score": visual_score,
        "visual_label": _visual_label(visual_score),
        "top_class_index": top1_idx,
        "top1_confidence": round(top1_conf, 4) if top1_conf is not None else None,
        "top2_confidence": round(top2_conf, 4) if top2_conf is not None else None,
        "top_margin": round(top_margin, 4) if top_margin is not None else None,
        "malware_probability": round(malware_probability, 4) if malware_probability is not None else None,
        "benign_probability": round(benign_probability, 4) if benign_probability is not None else None,
        "natural_image_confidence": round(natural_image_confidence, 4) if natural_image_confidence is not None else None,
        "activation_mean": round(activation_mean, 4) if activation_mean is not None else None,
        "activation_std": round(activation_std, 4) if activation_std is not None else None,
        "image_entropy": round(image_entropy, 4),
        "edge_density": round(edge_density, 4),
        "block_variance": round(block_variance, 4),
        "strong_signal_count": strong_signal_count,
        "logit": round(logit, 4) if logit is not None else None,
        "reasons": reasons,
        "custom_model_error": str(custom_error) if custom_error is not None else None,
        "error": None,
    }


def analyze_image_with_malware_cnn(
    image_path: str,
    weights_path: str | Path | None = None,
    variant_name: str = "nataraj",
) -> dict[str, Any]:
    expected_weights = str(Path(weights_path or CUSTOM_MODEL_PATH))

    try:
        torch, model, preprocess, device, metadata, custom_error = _load_model(weights_path)
    except Exception as exc:
        return {
            "available": False,
            "status": "cnn_unavailable",
            "mode": "unavailable",
            "model_name": "cnn",
            "weights": None,
            "expected_weights": expected_weights,
            "pretrained": True,
            "malware_specific": False,
            "binary_calibrated": False,
            "visual_score": None,
            "visual_label": None,
            "top_class_index": None,
            "top1_confidence": None,
            "top2_confidence": None,
            "top_margin": None,
            "malware_probability": None,
            "benign_probability": None,
            "natural_image_confidence": None,
            "activation_mean": None,
            "activation_std": None,
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
            "mode": metadata["mode"],
            "model_name": metadata["model_name"],
            "weights": metadata["weights"],
            "expected_weights": expected_weights,
            "pretrained": metadata["pretrained"],
            "malware_specific": metadata["malware_specific"],
            "binary_calibrated": metadata["malware_specific"],
            "visual_score": None,
            "visual_label": None,
            "top_class_index": None,
            "top1_confidence": None,
            "top2_confidence": None,
            "top_margin": None,
            "malware_probability": None,
            "benign_probability": None,
            "natural_image_confidence": None,
            "activation_mean": None,
            "activation_std": None,
            "image_entropy": None,
            "edge_density": None,
            "block_variance": None,
            "strong_signal_count": 0,
            "reasons": [],
            "error": f"Could not load grayscale image: {exc}",
        }

    return _analyze_loaded_image(
        gray_img=gray_img,
        torch=torch,
        model=model,
        preprocess=preprocess,
        device=device,
        metadata=metadata,
        expected_weights=expected_weights,
        custom_error=custom_error,
        variant_name=variant_name,
    )


def analyze_pil_image_with_malware_cnn(
    image: Image.Image,
    weights_path: str | Path | None = None,
    variant_name: str = "square",
) -> dict[str, Any]:
    expected_weights = str(Path(weights_path or CUSTOM_MODEL_PATH))

    try:
        torch, model, preprocess, device, metadata, custom_error = _load_model(weights_path)
    except Exception as exc:
        return {
            "available": False,
            "status": "cnn_unavailable",
            "mode": "unavailable",
            "model_name": "cnn",
            "weights": None,
            "expected_weights": expected_weights,
            "pretrained": True,
            "malware_specific": False,
            "binary_calibrated": False,
            "visual_score": None,
            "visual_label": None,
            "top_class_index": None,
            "top1_confidence": None,
            "top2_confidence": None,
            "top_margin": None,
            "malware_probability": None,
            "benign_probability": None,
            "natural_image_confidence": None,
            "activation_mean": None,
            "activation_std": None,
            "image_entropy": None,
            "edge_density": None,
            "block_variance": None,
            "strong_signal_count": 0,
            "reasons": [],
            "error": str(exc),
        }

    try:
        gray_img = image.convert("L")
    except Exception as exc:
        return {
            "available": False,
            "status": "image_load_failed",
            "mode": metadata["mode"],
            "model_name": metadata["model_name"],
            "weights": metadata["weights"],
            "expected_weights": expected_weights,
            "pretrained": metadata["pretrained"],
            "malware_specific": metadata["malware_specific"],
            "binary_calibrated": metadata["malware_specific"],
            "visual_score": None,
            "visual_label": None,
            "top_class_index": None,
            "top1_confidence": None,
            "top2_confidence": None,
            "top_margin": None,
            "malware_probability": None,
            "benign_probability": None,
            "natural_image_confidence": None,
            "activation_mean": None,
            "activation_std": None,
            "image_entropy": None,
            "edge_density": None,
            "block_variance": None,
            "strong_signal_count": 0,
            "reasons": [],
            "error": f"Could not prepare grayscale image: {exc}",
        }

    return _analyze_loaded_image(
        gray_img=gray_img,
        torch=torch,
        model=model,
        preprocess=preprocess,
        device=device,
        metadata=metadata,
        expected_weights=expected_weights,
        custom_error=custom_error,
        variant_name=variant_name,
    )


def ensemble_cnn_results(results: list[dict[str, Any]]) -> dict[str, Any]:
    usable = [result for result in results if result and result.get("available")]
    if not usable:
        return results[0] if results else {
            "available": False,
            "status": "cnn_unavailable",
            "reasons": ["No CNN results were available."],
        }

    if len(usable) == 1:
        single = dict(usable[0])
        single["ensemble_used"] = False
        return single

    malware_probabilities = [float(item.get("malware_probability", 0.0)) for item in usable]
    average_probability = sum(malware_probabilities) / len(malware_probabilities)
    disagreement = max(malware_probabilities) - min(malware_probabilities)
    agreement_penalty = min(0.20, disagreement * 0.5)
    ensemble_probability = max(0.0, min(1.0, average_probability - agreement_penalty))
    benign_probability = max(0.0, 1.0 - ensemble_probability)
    top_margin = abs(ensemble_probability - benign_probability)
    visual_score = int(round(ensemble_probability * 100.0))

    strongest_reasons: list[str] = []
    for item in usable:
        for reason in item.get("reasons", [])[:2]:
            if reason not in strongest_reasons:
                strongest_reasons.append(reason)

    if disagreement >= 0.35:
        strongest_reasons.append(
            "The CNN views disagreed noticeably, so the final malware probability was reduced."
        )

    best = max(usable, key=lambda item: float(item.get("calibration_reliability", 0.0)))
    ensemble = dict(best)
    ensemble.update(
        {
            "ensemble_used": True,
            "ensemble_variants": [
                {
                    "variant_name": item.get("variant_name"),
                    "malware_probability": item.get("malware_probability"),
                    "raw_malware_probability": item.get("raw_malware_probability"),
                    "visual_score": item.get("visual_score"),
                    "calibration_reliability": item.get("calibration_reliability"),
                }
                for item in usable
            ],
            "variant_name": "ensemble",
            "visual_score": visual_score,
            "visual_label": _visual_label(visual_score),
            "top_class_index": 0 if ensemble_probability >= benign_probability else 1,
            "top1_confidence": round(max(ensemble_probability, benign_probability), 4),
            "top2_confidence": round(min(ensemble_probability, benign_probability), 4),
            "top_margin": round(top_margin, 4),
            "malware_probability": round(ensemble_probability, 4),
            "benign_probability": round(benign_probability, 4),
            "natural_image_confidence": round(benign_probability, 4),
            "reasons": strongest_reasons[:6],
        }
    )
    return ensemble
