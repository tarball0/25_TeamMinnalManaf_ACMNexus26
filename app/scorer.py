from .signature import has_embedded_signature, signature_score_adjustment

COMMON_HELPER_APIS = {
    "CreateProcess",
    "CreateProcessA",
    "CreateProcessW",
    "GetProcAddress",
    "IsDebuggerPresent",
    "LoadLibrary",
    "LoadLibraryA",
    "LoadLibraryW",
    "VirtualAlloc",
    "VirtualProtect",
}


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


def compute_suspicion_score(
    pe_info: dict,
    cnn_info: dict | None = None,
    signature_info: dict | None = None,
) -> dict:
    rule_score = 0
    reasons = []

    is_pe = pe_info.get("is_pe", False)
    avg_entropy = float(pe_info.get("avg_section_entropy", 0.0))
    imports_count = int(pe_info.get("imports_count", 0))
    suspicious_names = pe_info.get("suspicious_section_names", []) or []
    num_sections = int(pe_info.get("num_sections", 0))
    section_entropies = pe_info.get("section_entropies", []) or []
    max_entropy = max(section_entropies) if section_entropies else avg_entropy
    suspicious_api_imports = pe_info.get("suspicious_api_imports", []) or []
    tls_callbacks = int(pe_info.get("tls_callbacks", 0) or 0)
    entry_point_section_entropy = pe_info.get("entry_point_section_entropy")
    has_certificate = bool(pe_info.get("has_certificate"))
    checksum_matches = pe_info.get("checksum_matches")
    timestamp_is_zero = bool(pe_info.get("timestamp_is_zero"))
    timestamp_is_future = bool(pe_info.get("timestamp_is_future"))
    timestamp_is_very_old = bool(pe_info.get("timestamp_is_very_old"))
    section_size_anomalies = pe_info.get("section_size_anomalies", []) or []
    resource_count = int(pe_info.get("resource_count", 0) or 0)
    overlay_ratio = float(pe_info.get("overlay_ratio", 0.0) or 0.0)

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

    if suspicious_api_imports:
        high_risk_api_imports = [
            api for api in suspicious_api_imports if api not in COMMON_HELPER_APIS
        ]
        if len(high_risk_api_imports) >= 4:
            rule_score += 18
            reasons.append(
                f"High-risk imported APIs found: {', '.join(high_risk_api_imports[:6])}."
            )
        elif high_risk_api_imports:
            rule_score += 10
            reasons.append(
                f"High-risk imported APIs found: {', '.join(high_risk_api_imports[:6])}."
            )
        elif imports_count <= 20:
            rule_score += 4
            reasons.append(
                f"Potentially suspicious helper APIs found: {', '.join(suspicious_api_imports[:6])}."
            )

    if tls_callbacks > 0:
        rule_score += 10
        reasons.append("TLS callbacks are present, which can be used for early execution before the normal entry point.")

    if entry_point_section_entropy is not None:
        ep_entropy = float(entry_point_section_entropy)
        if ep_entropy >= 7.3:
            rule_score += 14
            reasons.append("The entry-point section has high entropy, which can indicate packed startup code.")
        elif ep_entropy >= 6.8:
            rule_score += 6
            reasons.append("The entry-point section entropy is mildly elevated.")

    if section_size_anomalies:
        rule_score += 10
        reasons.append(
            f"Large raw/virtual section-size mismatches found in: {', '.join(section_size_anomalies[:5])}."
        )

    if checksum_matches is False:
        rule_score += 8
        reasons.append("The PE checksum field is present but does not match the computed checksum.")

    if timestamp_is_zero:
        rule_score += 8
        reasons.append("The PE timestamp is zeroed out.")
    elif timestamp_is_future:
        rule_score += 10
        reasons.append("The PE timestamp is in the future, which is unusual.")
    elif timestamp_is_very_old:
        rule_score += 6
        reasons.append("The PE timestamp is unusually old.")

    if not has_certificate and is_pe:
        rule_score += 6
        reasons.append("The PE file does not contain an embedded certificate table.")

    if resource_count == 0 and is_pe:
        rule_score += 4
        reasons.append("The PE file has no embedded resources.")

    if num_sections <= 2:
        rule_score += 10
        reasons.append("Very small number of sections can be suspicious.")
    elif num_sections >= 10:
        rule_score += 6
        reasons.append("Unusually large number of sections may indicate packing or tampering.")

    rule_score = _clamp(rule_score)
    signature_delta, signature_reason = signature_score_adjustment(signature_info or {})
    signed_file = has_embedded_signature(signature_info or {})

    cnn_available = bool(
        cnn_info
        and cnn_info.get("available")
        and cnn_info.get("visual_score") is not None
    )
    cnn_visual_score = int(cnn_info["visual_score"]) if cnn_available else None
    cnn_used = cnn_available

    cnn_weight = 0.0
    pe_weight = 1.0
    blend_mode = "pe_only"
    effective_signature_delta = signature_delta

    if cnn_available:
        top1_conf = float(cnn_info.get("top1_confidence", 0.0))
        malware_conf = float(cnn_info.get("malware_probability", top1_conf))
        top_margin = float(cnn_info.get("top_margin", 0.0))
        if signed_file:
            blend_mode = "signed_pe_only"
            reasons.insert(0, "Signed file caused the final score to ignore the CNN contribution.")
            final_score = _clamp(rule_score + effective_signature_delta)
        else:
            cnn_weight = 0.70
            pe_weight = 0.30
            blend_mode = "unsigned_cnn_pe_70_30"
            effective_signature_delta = 0
            final_score = _clamp((cnn_weight * cnn_visual_score) + (pe_weight * rule_score))

        if cnn_info.get("malware_specific", False) and not signed_file:
            can_force_high_floor = True
            if cnn_visual_score >= 85 and malware_conf >= 0.85:
                if can_force_high_floor:
                    final_score = max(final_score, 82)
                reasons.insert(
                    0,
                    f"EfficientNet malware CNN found a strong malware probability ({malware_conf:.1%} confidence).",
                )
            elif cnn_visual_score >= 70 and malware_conf >= 0.70:
                reasons.insert(
                    0,
                    f"EfficientNet malware CNN found a clear malware pattern ({malware_conf:.1%} confidence).",
                )
            elif cnn_visual_score >= 55:
                reasons.insert(
                    0,
                    f"EfficientNet malware CNN found a moderate malware pattern ({malware_conf:.1%} confidence).",
                )
            else:
                reasons.insert(
                    0,
                    f"EfficientNet malware CNN signal was weak ({malware_conf:.1%} confidence), so the final score stayed lower.",
                )
        elif not signed_file:
            if cnn_visual_score >= 80:
                reasons.insert(0, "Pretrained ResNet18 visual encoder found a strong byte-image anomaly.")
            elif cnn_visual_score >= 60:
                reasons.insert(0, "Pretrained ResNet18 visual encoder found a moderate byte-image anomaly.")
            else:
                reasons.insert(0, "Pretrained ResNet18 visual encoder found only a weak byte-image anomaly.")

        if top_margin >= 0.35 and not signed_file:
            reasons.append("CNN top-class margin was strong, so the visual match was relatively decisive.")
        elif top_margin >= 0.20 and not signed_file:
            reasons.append("CNN top-class margin was moderate.")

        if not signed_file:
            for item in (cnn_info.get("reasons") or [])[:3]:
                reasons.append(f"CNN: {item}")

        cnn_bonus = max(0, final_score - rule_score) if cnn_weight > 0 else 0
    else:
        if signature_info and signature_info.get("status") == "NotSigned":
            effective_signature_delta = 0
        final_score = _clamp(rule_score + effective_signature_delta)
        cnn_bonus = 0
        if cnn_info and cnn_info.get("status"):
            if cnn_info["status"] == "cnn_skipped":
                reasons.insert(0, cnn_info.get("reason") or "CNN was skipped.")
            elif cnn_info["status"] == "cnn_unavailable":
                reasons.insert(0, "CNN model is not installed, so this result uses PE-only analysis.")
            else:
                reasons.insert(0, f"CNN could not be used: {cnn_info['status']}.")

    final_score = _clamp(final_score)
    if signature_reason and effective_signature_delta != 0:
        reasons.insert(0, signature_reason)

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
        "signature_delta": effective_signature_delta,
        "signature_reason": signature_reason,
    }
