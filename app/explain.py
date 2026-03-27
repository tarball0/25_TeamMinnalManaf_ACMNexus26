def build_explanation(
    pe_info: dict,
    score_info: dict,
    image_info: dict,
    cnn_info: dict | None = None,
) -> str:
    lines = []

    lines.append(
        f"The uploaded file was converted into a grayscale image of size "
        f"{image_info['width']} x {image_info['height']}."
    )

    if image_info.get("sampled_for_image"):
        lines.append(
            f"The file was larger than the image budget, so bytes were sampled with stride "
            f"{image_info.get('sampling_stride', 1)} to build the image efficiently."
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
    else:
        lines.append("The file could not be fully parsed as a standard PE executable.")

    if cnn_info and cnn_info.get("available"):
        if cnn_info.get("malware_specific"):
            lines.append(
                f"A public pretrained malware-image CNN ({cnn_info.get('model_name', 'CNN')}) "
                f"re-checked the byte image after resizing it to 32 x 32 grayscale and produced "
                f"a CNN visual score of {cnn_info.get('visual_score', 0)}/100."
            )
            lines.append(
                f"The top CNN class confidence was {100.0 * float(cnn_info.get('top1_confidence', 0.0)):.1f}% "
                f"with a class margin of {100.0 * float(cnn_info.get('top_margin', 0.0)):.1f}%."
            )
        else:
            lines.append(
                f"A pretrained visual encoder ({cnn_info.get('model_name', 'CNN')}) inspected the grayscale byte image "
                f"and produced a visual anomaly score of {cnn_info.get('visual_score', 0)}/100."
            )
            lines.append(
                "This fallback CNN is a generic pretrained vision backbone, so it is used as a supporting signal rather than a malware-family classifier."
            )

        if score_info.get("blend_mode") == "cnn_supporting":
            lines.append(
                f"The final verdict uses the CNN only as a supporting anomaly signal: "
                f"{int(round(score_info.get('cnn_weight', 0.0) * 100))}% CNN and "
                f"{int(round(score_info.get('pe_weight', 1.0) * 100))}% PE."
            )
        else:
            lines.append(
                f"The final verdict blends "
                f"{int(round(score_info.get('cnn_weight', 0.0) * 100))}% CNN and "
                f"{int(round(score_info.get('pe_weight', 1.0) * 100))}% PE."
            )
    elif cnn_info:
        status = cnn_info.get("status", "unknown reason")
        error = cnn_info.get("error") or status

        if status == "cnn_unavailable":
            lines.append(
                "CNN analysis could not run because the pretrained malware model is not installed."
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
        "This remains a triage tool, not a full antivirus engine, but the CNN is now the main signal instead of a small auxiliary bonus."
    )

    return "\n".join(lines)
