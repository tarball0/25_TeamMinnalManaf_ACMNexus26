def build_explanation(pe_info: dict, score_info: dict, image_info: dict) -> str:
    lines = []

    lines.append(f"The uploaded file was converted into a grayscale image of size "
                 f"{image_info['width']} x {image_info['height']}.")

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

    lines.append(
        f"Based on the current rule-based checks, the file received a suspicion score of "
        f"{score_info['score']}/100 and is classified as: {score_info['label']}."
    )

    if score_info["reasons"]:
        lines.append("Main reasons:")
        for reason in score_info["reasons"]:
            lines.append(f"- {reason}")

    lines.append(
        "This is a hackathon MVP and not a full antivirus engine. "
        "It gives an explainable early warning based on file structure, entropy, and image pattern generation."
    )

    return "\n".join(lines)
