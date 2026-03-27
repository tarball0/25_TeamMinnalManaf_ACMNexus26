def compute_suspicion_score(pe_info: dict) -> dict:
    score = 0
    reasons = []

    if not pe_info.get("is_pe", False):
        score += 30
        reasons.append("File could not be parsed as a normal PE executable.")

    avg_entropy = pe_info.get("avg_section_entropy", 0.0)
    if avg_entropy >= 7.2:
        score += 30
        reasons.append("High average section entropy may suggest packing or obfuscation.")
    elif avg_entropy >= 6.8:
        score += 20
        reasons.append("Moderately high entropy may indicate compression or unusual structure.")

    imports_count = pe_info.get("imports_count", 0)
    if imports_count <= 5:
        score += 20
        reasons.append("Very low import count may indicate a packed or minimized binary.")
    elif imports_count <= 20:
        score += 10
        reasons.append("Low import count may be slightly suspicious.")

    suspicious_names = pe_info.get("suspicious_section_names", [])
    if suspicious_names:
        score += 25
        reasons.append(f"Suspicious section names found: {', '.join(suspicious_names)}.")

    num_sections = pe_info.get("num_sections", 0)
    if num_sections <= 2:
        score += 10
        reasons.append("Very small number of sections can be suspicious.")
    elif num_sections >= 8:
        score += 5
        reasons.append("Unusually high section count may indicate tampering or packing.")

    score = min(score, 100)

    if score >= 70:
        label = "Highly Suspicious / Possibly Packed"
    elif score >= 40:
        label = "Moderately Suspicious"
    else:
        label = "Low Suspicion"

    return {
        "score": score,
        "label": label,
        "reasons": reasons,
    }