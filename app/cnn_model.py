from __future__ import annotations

from pathlib import Path
from typing import Any

import numpy as np
from PIL import Image

CUSTOM_MODEL_PATH = Path(__file__).resolve().parent / "models" / "ResNet-custom.pth"
INPUT_SIZE = 32
NUM_CLASSES = 8


def _safe_import_torchvision():
    try:
        import torch
        import torch.nn as nn
        from torchvision import models, transforms
        return torch, nn, models, transforms, None
    except Exception as exc:
        return None, None, None, None, exc


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
        return "Strong visual anomaly"
    if score >= 60:
        return "Moderate visual anomaly"
    if score >= 40:
        return "Weak visual anomaly"
    return "Low CNN evidence"


def conv3x3(nn, in_channels: int, out_channels: int, stride: int = 1):
    return nn.Conv2d(
        in_channels,
        out_channels,
        kernel_size=3,
        stride=stride,
        padding=1,
        bias=False,
    )


def make_residual_block_class(nn):
    class ResidualBlock(nn.Module):
        def __init__(
            self,
            in_channels: int,
            out_channels: int,
            stride: int = 1,
            downsample=None,
        ):
            super().__init__()
            self.conv1 = conv3x3(nn, in_channels, out_channels, stride)
            self.bn1 = nn.BatchNorm2d(out_channels)
            self.relu = nn.ReLU(inplace=True)
            self.conv2 = conv3x3(nn, out_channels, out_channels)
            self.bn2 = nn.BatchNorm2d(out_channels)
            self.downsample = downsample

        def forward(self, x):
            residual = x

            out = self.conv1(x)
            out = self.bn1(out)
            out = self.relu(out)

            out = self.conv2(out)
            out = self.bn2(out)

            if self.downsample is not None:
                residual = self.downsample(x)

            out += residual
            out = self.relu(out)
            return out

    return ResidualBlock


def make_resnet_class(nn):
    ResidualBlock = make_residual_block_class(nn)

    class ResNetCustom(nn.Module):
        def __init__(self, layers, num_classes: int = NUM_CLASSES):
            super().__init__()
            self.in_channels = 16
            self.conv = conv3x3(nn, 1, 16)
            self.bn = nn.BatchNorm2d(16)
            self.relu = nn.ReLU(inplace=True)

            self.layer1 = self.make_layer(ResidualBlock, 16, layers[0])
            self.layer2 = self.make_layer(ResidualBlock, 32, layers[0], stride=2)
            self.layer3 = self.make_layer(ResidualBlock, 64, layers[1], stride=2)

            self.avg_pool = nn.AvgPool2d(8)
            self.fc = nn.Linear(64, num_classes)

        def make_layer(self, block, out_channels: int, blocks: int, stride: int = 1):
            downsample = None
            if stride != 1 or self.in_channels != out_channels:
                downsample = nn.Sequential(
                    conv3x3(nn, self.in_channels, out_channels, stride=stride),
                    nn.BatchNorm2d(out_channels),
                )

            layers = [block(self.in_channels, out_channels, stride, downsample)]
            self.in_channels = out_channels

            for _ in range(1, blocks):
                layers.append(block(out_channels, out_channels))

            return nn.Sequential(*layers)

        def forward(self, x):
            out = self.conv(x)
            out = self.bn(out)
            out = self.relu(out)

            out = self.layer1(out)
            out = self.layer2(out)
            out = self.layer3(out)

            out = self.avg_pool(out)
            out = out.view(out.size(0), -1)
            out = self.fc(out)
            return out

    return ResNetCustom


def _build_custom_model(torch, nn, transforms, weights_path: str | Path | None = None):
    resolved_weights = Path(weights_path or CUSTOM_MODEL_PATH)
    if not resolved_weights.exists():
        raise FileNotFoundError(f"Missing pretrained malware CNN weights: {resolved_weights}")

    ResNetCustom = make_resnet_class(nn)
    model = ResNetCustom(layers=[2, 1, 1, 2], num_classes=NUM_CLASSES)
    checkpoint = torch.load(resolved_weights, map_location="cpu")

    if isinstance(checkpoint, dict) and "state_dict" in checkpoint:
      state_dict = checkpoint["state_dict"]
    else:
      state_dict = checkpoint

    if not isinstance(state_dict, dict):
        raise RuntimeError("Checkpoint format is not a valid PyTorch state_dict.")

    model.load_state_dict(_clean_state_dict(state_dict), strict=True)
    preprocess = transforms.Compose(
        [
            transforms.Resize((INPUT_SIZE, INPUT_SIZE)),
            transforms.ToTensor(),
        ]
    )

    return model, preprocess, {
        "mode": "custom",
        "model_name": "ResNet-custom",
        "weights": str(resolved_weights),
        "pretrained": True,
        "malware_specific": True,
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
                    mean=[0.485, 0.456, 0.406],
                    std=[0.229, 0.224, 0.225],
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
    }


def _load_model(weights_path: str | Path | None = None):
    torch, nn, models, transforms, import_error = _safe_import_torchvision()
    if import_error is not None:
        raise RuntimeError(
            "PyTorch and torchvision are required. Install torch and torchvision first."
        ) from import_error

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    custom_error = None
    try:
        model, preprocess, metadata = _build_custom_model(torch, nn, transforms, weights_path)
    except Exception as exc:
        custom_error = exc
        try:
            model, preprocess, metadata = _build_pretrained_resnet18(torch, models, transforms)
        except Exception as fallback_exc:
            raise RuntimeError(
                f"Custom malware CNN unavailable ({custom_error}). "
                "Fallback ResNet18 could not be loaded either. "
                "If this is the first run, connect once to the internet so torchvision can cache the pretrained weights."
            ) from fallback_exc

    model.eval().to(device)
    return torch, model, preprocess, device, metadata, custom_error


def analyze_image_with_malware_cnn(
    image_path: str,
    weights_path: str | Path | None = None,
) -> dict[str, Any]:
    try:
        torch, model, preprocess, device, metadata, custom_error = _load_model(weights_path)
    except Exception as exc:
        return {
            "available": False,
            "status": "cnn_unavailable",
            "mode": "unavailable",
            "model_name": "cnn",
            "weights": None,
            "expected_weights": str(Path(weights_path or CUSTOM_MODEL_PATH)),
            "pretrained": True,
            "malware_specific": False,
            "binary_calibrated": False,
            "visual_score": None,
            "visual_label": None,
            "top_class_index": None,
            "top1_confidence": None,
            "top2_confidence": None,
            "top_margin": None,
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
        model_input_image = gray_img if metadata["mode"] == "custom" else gray_img.convert("RGB")
    except Exception as exc:
        return {
            "available": False,
            "status": "image_load_failed",
            "mode": metadata["mode"],
            "model_name": metadata["model_name"],
            "weights": metadata["weights"],
            "expected_weights": str(Path(weights_path or CUSTOM_MODEL_PATH)),
            "pretrained": metadata["pretrained"],
            "malware_specific": metadata["malware_specific"],
            "binary_calibrated": metadata["malware_specific"],
            "visual_score": None,
            "visual_label": None,
            "top_class_index": None,
            "top1_confidence": None,
            "top2_confidence": None,
            "top_margin": None,
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

    tensor = preprocess(model_input_image).unsqueeze(0).to(device)

    with torch.no_grad():
        outputs = model(tensor)

    gray_array = np.asarray(gray_img, dtype=np.float32) / 255.0
    image_entropy = _grayscale_entropy(gray_array)
    edge_density = _edge_density(gray_array)
    block_variance = _block_variance(gray_array)

    reasons: list[str] = []
    strong_signal_count = 0

    if metadata["mode"] == "custom":
        probs = torch.softmax(outputs, dim=1)[0].detach().cpu().numpy()
        sorted_idx = np.argsort(probs)[::-1]
        top1_idx = int(sorted_idx[0])
        top2_idx = int(sorted_idx[1]) if len(sorted_idx) > 1 else top1_idx
        top1_conf = float(probs[top1_idx])
        top2_conf = float(probs[top2_idx]) if len(sorted_idx) > 1 else 0.0
        top_margin = max(0.0, top1_conf - top2_conf)

        entropy_score = _scaled_score(image_entropy, 6.5, 7.5)
        edge_score = _scaled_score(edge_density, 0.07, 0.18)
        variance_score = _scaled_score(block_variance, 0.003, 0.018)

        visual_score = int(
            round(
                min(
                    100.0,
                    (0.58 * top1_conf * 100.0)
                    + (0.22 * top_margin * 100.0)
                    + (0.10 * entropy_score)
                    + (0.05 * edge_score)
                    + (0.05 * variance_score),
                )
            )
        )

        if top1_conf >= 0.85:
            reasons.append("The pretrained malware-image CNN found a very strong family-style match.")
            strong_signal_count += 1
        elif top1_conf >= 0.70:
            reasons.append("The pretrained malware-image CNN found a clear family-style match.")
            strong_signal_count += 1
        elif top1_conf >= 0.55:
            reasons.append("The CNN found a moderate family-style match.")

        if top_margin >= 0.35:
            reasons.append("The gap between the top two CNN classes is large, which makes the visual match more decisive.")
            strong_signal_count += 1
        elif top_margin >= 0.20:
            reasons.append("The gap between the top two CNN classes is moderate.")

        natural_image_confidence = None
        activation_mean = None
        activation_std = None
    else:
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

        top1_idx = None
        top1_conf = round(visual_score / 100.0, 4)
        top2_conf = None
        top_margin = round(max(0.0, top1_conf - 0.5), 4)
        natural_image_confidence = round(max(0.0, 1.0 - top1_conf), 4)

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
        "expected_weights": str(Path(weights_path or CUSTOM_MODEL_PATH)),
        "pretrained": metadata["pretrained"],
        "malware_specific": metadata["malware_specific"],
        "binary_calibrated": metadata["malware_specific"],
        "visual_score": visual_score,
        "visual_label": _visual_label(visual_score),
        "top_class_index": top1_idx,
        "top1_confidence": round(top1_conf, 4) if top1_conf is not None else None,
        "top2_confidence": round(top2_conf, 4) if top2_conf is not None else None,
        "top_margin": round(top_margin, 4) if top_margin is not None else None,
        "natural_image_confidence": natural_image_confidence,
        "activation_mean": round(activation_mean, 4) if activation_mean is not None else None,
        "activation_std": round(activation_std, 4) if activation_std is not None else None,
        "image_entropy": round(image_entropy, 4),
        "edge_density": round(edge_density, 4),
        "block_variance": round(block_variance, 4),
        "strong_signal_count": strong_signal_count,
        "reasons": reasons,
        "custom_model_error": str(custom_error) if custom_error is not None else None,
        "error": None,
    }
