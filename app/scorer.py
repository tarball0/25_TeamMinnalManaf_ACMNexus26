def compute_suspicion_score(pe_info: dict, cnn_info: dict | None = None) -> dict:
    rule_score = 0
    reasons = []

    if not pe_info.get("is_pe", False):
        rule_score += 30
        reasons.append("File could not be parsed as a normal PE executable.")

    avg_entropy = pe_info.get("avg_section_entropy", 0.0)
    if avg_entropy >= 7.2:
        rule_score += 30
        reasons.append("High average section entropy may suggest packing or obfuscation.")
    elif avg_entropy >= 6.8:
        rule_score += 20
        reasons.append("Moderately high entropy may indicate compression or unusual structure.")

    imports_count = pe_info.get("imports_count", 0)
    if imports_count <= 5:
        rule_score += 20
        reasons.append("Very low import count may indicate a packed or minimized binary.")
    elif imports_count <= 20:
        rule_score += 10
        reasons.append("Low import count may be slightly suspicious.")

    suspicious_names = pe_info.get("suspicious_section_names", [])
    if suspicious_names:
        rule_score += 25
        reasons.append(f"Suspicious section names found: {', '.join(suspicious_names)}.")

    num_sections = pe_info.get("num_sections", 0)
    if num_sections <= 2:
        rule_score += 10
        reasons.append("Very small number of sections can be suspicious.")
    elif num_sections >= 8:
        rule_score += 5
        reasons.append("Unusually high section count may indicate tampering or packing.")

    rule_score = min(rule_score, 100)

    cnn_used = bool(cnn_info and cnn_info.get("available") and cnn_info.get("visual_score") is not None)
    cnn_visual_score = None

    if cnn_used:
        cnn_visual_score = int(cnn_info["visual_score"])
        final_score = round((0.70 * rule_score) + (0.30 * cnn_visual_score))
        reasons.append(
            f"Pretrained CNN visual encoder contributed {cnn_visual_score}/100 from the grayscale byte image."
        )

        for item in cnn_info.get("reasons", [])[:2]:
            reasons.append(f"CNN: {item}")
    else:
        final_score = rule_score
        if cnn_info and cnn_info.get("status"):
            reasons.append(f"Pretrained CNN could not be used: {cnn_info['status']}.")

    final_score = min(final_score, 100)

    if final_score >= 70:
        label = "Highly Suspicious / Possibly Packed"
    elif final_score >= 40:
        label = "Moderately Suspicious"
    else:
        label = "Low Suspicion"

    return {
        "score": final_score,
        "label": label,
        "reasons": reasons,
        "rule_score": rule_score,
        "cnn_used": cnn_used,
        "cnn_visual_score": cnn_visual_score,
    }
