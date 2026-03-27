import math
from collections import Counter

import pefile


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0

    counts = Counter(data)
    total = len(data)
    entropy = 0.0

    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)

    return entropy


def extract_pe_features(file_path: str) -> dict:
    result = {
        "is_pe": False,
        "num_sections": 0,
        "section_names": [],
        "section_entropies": [],
        "avg_section_entropy": 0.0,
        "imports_count": 0,
        "has_debug": False,
        "has_tls": False,
        "entry_point": None,
        "suspicious_section_names": [],
        "parse_error": None,
    }

    try:
        pe = pefile.PE(file_path)
        result["is_pe"] = True
        result["num_sections"] = len(pe.sections)
        result["entry_point"] = int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)

        section_entropies = []
        section_names = []
        suspicious_names = []

        known_suspicious = {
            ".upx", "upx0", "upx1", "upx2",
            ".aspack", ".adata", ".packed", "pec1", "pec2"
        }

        for section in pe.sections:
            name = section.Name.decode(errors="ignore").strip("\x00")
            section_names.append(name)

            data = section.get_data()
            ent = shannon_entropy(data)
            section_entropies.append(round(ent, 4))

            lower_name = name.lower()
            if lower_name in known_suspicious or "upx" in lower_name or "pack" in lower_name:
                suspicious_names.append(name)

        result["section_names"] = section_names
        result["section_entropies"] = section_entropies
        result["avg_section_entropy"] = round(
            sum(section_entropies) / len(section_entropies), 4
        ) if section_entropies else 0.0
        result["suspicious_section_names"] = suspicious_names

        imports_count = 0
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                if hasattr(entry, "imports") and entry.imports is not None:
                    imports_count += len(entry.imports)
        result["imports_count"] = imports_count

        result["has_debug"] = hasattr(pe, "DIRECTORY_ENTRY_DEBUG")
        result["has_tls"] = hasattr(pe, "DIRECTORY_ENTRY_TLS")

        pe.close()
        return result

    except Exception as e:
        result["parse_error"] = str(e)
        return result


if __name__ == "__main__":
    # Example usage
    import sys
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        result = extract_pe_features(file_path)
        print(result)
    else:
        print("Usage: python pe_features.py <file_path>")