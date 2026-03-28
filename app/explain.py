def build_explanation(
    pe_info: dict,
    score_info: dict,
    image_info: dict,
    cnn_info: dict | None = None,
    signature_info: dict | None = None,
) -> str:
    lines = []

    lines.append(
        f"The uploaded file was converted into a grayscale image of size "
        f"{image_info['width']} x {image_info['height']}."
    )

    if image_info.get("reduction_mode") == "nataraj_width_mapping":
        lines.append(
            "The byte image was built with the Nataraj-style width mapping used during training, "
            "padding the final row with zeros when needed."
        )

    if pe_info.get("is_pe"):
        lines.append(
            f"The file appears to be a valid PE executable with "
            f"{pe_info.get('num_sections', 0)} sections and "
            f"{pe_info.get('imports_count', 0)} imported functions."
        )
        lines.append(
            f"The average section entropy is {pe_info.get('avg_section_entropy', 0.0):.2f}."
        )
        if pe_info.get("entry_point_section"):
            lines.append(
                f"The entry point is in section {pe_info.get('entry_point_section')} "
                f"with entropy {float(pe_info.get('entry_point_section_entropy') or 0.0):.2f}."
            )
        lines.append(
            f"TLS callbacks: {pe_info.get('tls_callbacks', 0)}. "
            f"Resources: {pe_info.get('resource_count', 0)}. "
            f"Certificate present: {'Yes' if pe_info.get('has_certificate') else 'No'}."
        )
    else:
        lines.append("The file could not be fully parsed as a standard PE executable.")

    if signature_info:
        if signature_info.get("available"):
            status = signature_info.get("status", "Unknown")
            subject = signature_info.get("subject") or "Unknown publisher"
            lines.append(
                f"Authenticode signature status: {status}. Publisher: {subject}."
            )
            if signature_info.get("trusted_publisher"):
                lines.append("The publisher matches the trusted allowlist, so the signature reduced the final score.")
            elif status == "Valid":
                lines.append("The file is signed, but the publisher is not in the trusted allowlist, so only a small trust bonus was applied.")
        else:
            lines.append(
                f"Authenticode signature check was unavailable: {signature_info.get('status_message', 'unknown reason')}."
            )

    if cnn_info and cnn_info.get("available"):
        if cnn_info.get("malware_specific"):
            lines.append(
                f"A fine-tuned malware CNN ({cnn_info.get('model_name', 'CNN')}) "
                f"re-checked the byte image after resizing it to "
                f"{cnn_info.get('input_size', 224)} x {cnn_info.get('input_size', 224)}. It produced "
                f"a CNN visual score of {cnn_info.get('visual_score', 0)}/100."
            )
            lines.append(
                f"The model estimated malware probability at "
                f"{100.0 * float(cnn_info.get('malware_probability', 0.0)):.1f}% and safe probability at "
                f"{100.0 * float(cnn_info.get('benign_probability', 0.0)):.1f}% "
                f"with a decision margin of {100.0 * float(cnn_info.get('top_margin', 0.0)):.1f}%."
            )
        else:
            lines.append(
                f"A pretrained visual encoder ({cnn_info.get('model_name', 'CNN')}) inspected the grayscale byte image "
                f"and produced a visual anomaly score of {cnn_info.get('visual_score', 0)}/100."
            )
            lines.append(
                "This fallback CNN is a generic pretrained vision backbone, so it is used as a supporting signal rather than a malware-family classifier."
            )

        if score_info.get("blend_mode") == "signed_pe_only":
            lines.append(
                "The file is signed, so the final verdict ignores the CNN score and uses PE headers plus signature status."
            )
        elif score_info.get("blend_mode") == "unsigned_cnn_pe_70_30":
            lines.append(
                "The final verdict uses only the CNN score and PE headers: 70% CNN and 30% PE."
            )
        else:
            lines.append("The final verdict uses the available PE and signature signals.")
    elif cnn_info:
        status = cnn_info.get("status", "unknown reason")
        error = cnn_info.get("error") or status

        if status == "cnn_skipped":
            lines.append(
                f"CNN analysis was skipped because: {cnn_info.get('reason', 'the signature and PE checks were sufficient')}."
            )
        elif status == "cnn_unavailable":
            lines.append(
                "CNN analysis could not run because the EfficientNet malware model is not installed."
            )
            lines.append(f"Expected model file: {cnn_info.get('expected_weights') or 'Unavailable'}.")
            lines.append(f"Fallback reason: {error}.")
        else:
            lines.append(
                f"CNN analysis could not run because: {error}."
            )

    lines.append(
        f"Based on the combined analysis, the file received a suspicion score of "
        f"{score_info['score']}/100 and is classified as: {score_info['label']}."
    )

    lines.append(
        f"PE-only score: {score_info.get('rule_score', 0)}/100."
    )

    if score_info["reasons"]:
        lines.append("Main reasons:")
        for reason in score_info["reasons"]:
            lines.append(f"- {reason}")

    lines.append(
        "This remains a triage tool, not a full antivirus engine, and now follows the signed-vs-unsigned fusion rule directly."
    )

    return "\n".join(lines)
