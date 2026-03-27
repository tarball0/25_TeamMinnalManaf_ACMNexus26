import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.main import analyze_file  # noqa: E402


def make_absolute(path_str: str) -> str:
    p = Path(path_str)
    if p.is_absolute():
        return str(p)
    return str((ROOT / p).resolve())


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"ok": False, "error": "No file path was provided."}))
        sys.exit(1)

    file_path = Path(sys.argv[1]).expanduser().resolve()

    if not file_path.exists():
        print(json.dumps({"ok": False, "error": f"File not found: {file_path}"}))
        sys.exit(1)

    try:
        result = analyze_file(str(file_path))

        image_path = result.get("image_info", {}).get("image_path")
        if image_path:
            result["image_info"]["image_path"] = make_absolute(image_path)

        print(json.dumps({"ok": True, "result": result}))
    except Exception as e:
        print(json.dumps({"ok": False, "error": str(e)}))
        sys.exit(1)


if __name__ == "__main__":
    main()
