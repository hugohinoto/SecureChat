import json
import sys
from pathlib import Path

report_path = Path(sys.argv[1] if len(sys.argv) > 1 else "semgrep-results.json")
if not report_path.is_file():
    print("Semgrep report is missing; scan result is unverified.")
    raise SystemExit(1)

try:
    report = json.loads(report_path.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError) as error:
    print(f"Semgrep report could not be read: {error}")
    raise SystemExit(1)

errors = report.get("errors") or []
if errors:
    print("Semgrep reported scan errors; a clean result cannot be claimed:")
    for item in errors:
        print(json.dumps(item, ensure_ascii=False))
    raise SystemExit(1)

findings = report.get("results") or []
blocking = [item for item in findings if str(item.get("severity", "")).upper() in {"ERROR", "BLOCKER"}]
if findings:
    print(f"Semgrep findings: {len(findings)}")
    for item in findings:
        start = item.get("start") or {}
        end = item.get("end") or {}
        print(
            f"{item.get('severity', 'UNKNOWN')} {item.get('check_id', 'unknown')} "
            f"{item.get('path', 'unknown')}:{start.get('line', '?')}:{start.get('col', '?')}-"
            f"{end.get('line', '?')}:{end.get('col', '?')}"
        )
        print(f"  {item.get('extra', {}).get('message', 'No finding message provided')}")
else:
    print("Semgrep reported no findings.")

if blocking:
    print(f"Blocking Semgrep findings: {len(blocking)}")
    raise SystemExit(1)
