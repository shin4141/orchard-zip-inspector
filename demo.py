"""Create synthetic ZIPs and run the real inspector; save reproducible outputs."""

import argparse
import hashlib
import json
from pathlib import Path

from synthetic import demo_fixtures
from zip_inspector import inspect_zip


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    summary = {}
    for name, data in demo_fixtures().items():
        zip_path = args.output_dir / (name + ".zip")
        zip_path.write_bytes(data)
        report = inspect_zip(zip_path)
        assert report["input"]["sha256"] == hashlib.sha256(data).hexdigest()
        (args.output_dir / (name + ".json")).write_text(
            json.dumps(report, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
        summary[name] = {
            "inspection_status": report["inspection_status"],
            "prompt_injection": report["prompt_injection"],
            "gate": report["gate"],
            "entries": report["coverage"]["listed_entries"],
            "findings": len(report["findings"]),
            "unknown_conditions": report["unknown_conditions"],
        }
    print(json.dumps(summary, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
