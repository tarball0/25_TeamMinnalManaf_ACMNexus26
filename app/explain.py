from __future__ import annotations


def build_explanation(
    pe_info: dict,
    score_info: dict,
    image_info: dict,
    cnn_info: dict | None = None,
) -> str:
    lines: list[str] = []

    lines.append(
        f"The uploaded file was converted into a grayscale image of size "
        f"{image_info['width']} x {image_info['height']}."
    )

    if image_info.get("sampled_for_image"):
        lines.append(
            f"The file was larger than the image budget, so bytes were sampled with stride "
            f"{image_info.get('sampling_stride', 1)} to build the image."
        )

    if pe_info.get("is_pe"):
        lines.append(
            f"The file appears to be a valid PE executable with "
            f"{pe_info.get('num_sections', 0)} sections and "
            f"{pe_info.get('imports_count', 0)} imported functions."
        )
        lines.append(
            f"Average section entropy is {pe_info.get('avg_section_entropy', 0.0):.2f}, "
            f"and maximum section entropy is {pe_info.get('max_section_entropy', 0.0):.2f}."
        )
    else:
        lines.append("The file could not be fully parsed as a standard PE executable.")

    if cnn_info and cnn_info.get("available"):
        probability = 100.0 * float(cnn_info.get("malware_probability", 0.0))
        malware_score = int(cnn_info.get("malware_score", 0))
        lines.append(
            f"A malware-trained CNN ({cnn_info.get('model_name', 'CNN')}) inspected the byte image "
            f"and predicted malware probability {probability:.1f}% "
            f"(CNN score {malware_score}/100)."
        )
        lines.append(
            f"The final verdict uses CNN-primary fusion: "
            f"{int(round(score_info.get('cnn_weight', 0.7) * 100))}% CNN and "
            f"{int(round(score_info.get('pe_weight', 0.3) * 100))}% PE features."
        )
        lines.append(
            f"PE risk alone was {score_info.get('rule_score', 0)}/100, while the final combined score is "
            f"{score_info.get('score', 0)}/100."
        )
    elif cnn_info:
        lines.append(
            f"Malware CNN analysis was unavailable because: "
            f"{cnn_info.get('error') or cnn_info.get('status', 'unknown reason')}."
        )
        lines.append("The verdict therefore falls back to PE-based analysis only.")

    lines.append(
        f"Final classification: {score_info['label']} "
        f"with a suspicion score of {score_info['score']}/100."
    )

    if score_info.get("reasons"):
        lines.append("Main reasons:")
        for reason in score_info["reasons"]:
            lines.append(f"- {reason}")

    lines.append(
        "This is still a triage tool, not a full antivirus engine, but the CNN is now the primary model "
        "instead of being just a small auxiliary signal."
    )

    return "\n".join(lines)
