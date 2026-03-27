def _clamp(value: float) -> int:
    return max(0, min(100, int(round(value))))


def _label_from_score(score: int) -> str:
    if score >= 80:
        return "Highly Suspicious"
    if score >= 60:
        return "Suspicious"
    if score >= 40:
        return "Needs Review"
    return "Low Suspicion"


def compute_suspicion_score(pe_info: dict, cnn_info: dict | None = None) -> dict:
    rule_score = 0
    reasons = []

    is_pe = pe_info.get("is_pe", False)
    avg_entropy = float(pe_info.get("avg_section_entropy", 0.0))
    imports_count = int(pe_info.get("imports_count", 0))
    suspicious_names = pe_info.get("suspicious_section_names", []) or []
    num_sections = int(pe_info.get("num_sections", 0))
    section_entropies = pe_info.get("section_entropies", []) or []
    max_entropy = max(section_entropies) if section_entropies else avg_entropy

    if not is_pe:
        rule_score += 35
        reasons.append("File could not be parsed as a normal PE executable.")

    if avg_entropy >= 7.4:
        rule_score += 28
        reasons.append("Very high average section entropy may suggest packing or strong obfuscation.")
    elif avg_entropy >= 7.0:
        rule_score += 18
        reasons.append("High average section entropy may indicate compression or unusual structure.")
    elif avg_entropy >= 6.8:
        rule_score += 8
        reasons.append("Average section entropy is mildly elevated.")

    if max_entropy >= 7.8:
        rule_score += 18
        reasons.append("At least one section has very high entropy.")
    elif max_entropy >= 7.3:
        rule_score += 10
        reasons.append("At least one section has high entropy.")

    if imports_count == 0:
        rule_score += 22
        reasons.append("No imports were found, which is often seen in packed or manually resolved binaries.")
    elif imports_count <= 5:
        rule_score += 16
        reasons.append("Very low import count may indicate a packed or minimized binary.")
    elif imports_count <= 15:
        rule_score += 7
        reasons.append("Low import count is mildly suspicious.")

    if suspicious_names:
        rule_score += 22
        reasons.append(f"Suspicious section names found: {', '.join(suspicious_names)}.")

    if num_sections <= 2:
        rule_score += 10
        reasons.append("Very small number of sections can be suspicious.")
    elif num_sections >= 10:
        rule_score += 6
        reasons.append("Unusually large number of sections may indicate packing or tampering.")

    rule_score = _clamp(rule_score)

    cnn_available = bool(
        cnn_info
        and cnn_info.get("available")
        and cnn_info.get("visual_score") is not None
    )
    cnn_visual_score = int(cnn_info["visual_score"]) if cnn_available else None
    cnn_used = cnn_available

    cnn_weight = 0.75
    pe_weight = 0.25
    blend_mode = "pe_only"

    if cnn_available:
        if cnn_info and not cnn_info.get("malware_specific", False):
            cnn_weight = 0.35
            pe_weight = 0.65
            blend_mode = "cnn_supporting"
        else:
            blend_mode = "cnn_primary"

        top1_conf = float(cnn_info.get("top1_confidence", 0.0))
        top_margin = float(cnn_info.get("top_margin", 0.0))

        final_score = _clamp((cnn_weight * cnn_visual_score) + (pe_weight * rule_score))

        if cnn_info.get("malware_specific", False):
            if cnn_visual_score >= 85 and top1_conf >= 0.85:
                final_score = max(final_score, 82)
                reasons.insert(
                    0,
                    f"Public pretrained malware-image CNN found a strong visual malware-family match ({top1_conf:.1%} confidence).",
                )
            elif cnn_visual_score >= 70 and top1_conf >= 0.70:
                reasons.insert(
                    0,
                    f"CNN found a clear malware-image pattern ({top1_conf:.1%} confidence).",
                )
            elif cnn_visual_score >= 55:
                reasons.insert(
                    0,
                    f"CNN found a moderate malware-image pattern ({top1_conf:.1%} confidence).",
                )
            else:
                reasons.insert(
                    0,
                    f"CNN signal was weak ({top1_conf:.1%} confidence), so the final score stayed lower.",
                )
        else:
            if cnn_visual_score >= 80:
                reasons.insert(0, "Pretrained ResNet18 visual encoder found a strong byte-image anomaly.")
            elif cnn_visual_score >= 60:
                reasons.insert(0, "Pretrained ResNet18 visual encoder found a moderate byte-image anomaly.")
            else:
                reasons.insert(0, "Pretrained ResNet18 visual encoder found only a weak byte-image anomaly.")

        if top_margin >= 0.35:
            reasons.append("CNN top-class margin was strong, so the visual match was relatively decisive.")
        elif top_margin >= 0.20:
            reasons.append("CNN top-class margin was moderate.")

        for item in (cnn_info.get("reasons") or [])[:3]:
            reasons.append(f"CNN: {item}")

        cnn_bonus = max(0, final_score - rule_score)
    else:
        final_score = rule_score
        cnn_bonus = 0
        if cnn_info and cnn_info.get("status"):
            if cnn_info["status"] == "cnn_unavailable":
                reasons.insert(0, "CNN model is not installed, so this result uses PE-only analysis.")
            else:
                reasons.insert(0, f"CNN could not be used: {cnn_info['status']}.")

    final_score = _clamp(final_score)

    return {
        "score": final_score,
        "label": _label_from_score(final_score),
        "reasons": reasons,
        "rule_score": rule_score,
        "cnn_used": cnn_used,
        "cnn_visual_score": cnn_visual_score,
        "cnn_bonus": cnn_bonus,
        "cnn_weight": cnn_weight if cnn_available else 0.0,
        "pe_weight": pe_weight if cnn_available else 1.0,
        "blend_mode": blend_mode,
    }
