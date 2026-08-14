#!/usr/bin/env python3
"""
Validate audit JSON outputs against the schemas in docs/schemas/.

Usage:
    python scripts/schema_check.py                      # validate experiment/results/**/*.json
    python scripts/schema_check.py --file <path> [--schema <result|final-result|trace>]

Schema resolution for experiment/results files (by filename):
    <skill>_trace.json  -> docs/schemas/trace.schema.json
    result.json         -> docs/schemas/result.schema.json   (deterministic pipeline output)
    other aggregated files (batch_*.json) are skipped.

Exit code 0 = all valid, 1 = at least one invalid (or no jsonschema installed).
"""

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCHEMAS = {
    "result": REPO / "docs" / "schemas" / "result.schema.json",
    "final-result": REPO / "docs" / "schemas" / "final-result.schema.json",
    "trace": REPO / "docs" / "schemas" / "trace.schema.json",
}
RESULTS_DIR = REPO / "experiment" / "results"


def _emit(text: str) -> None:
    """Windows console-safe UTF-8 output."""
    try:
        sys.stdout.buffer.write(text.encode("utf-8"))
        sys.stdout.buffer.write(b"\n")
    except Exception:
        print(text)


def load_schema(name: str):
    try:
        import jsonschema
    except ImportError:
        _emit("ERROR: 'jsonschema' is not installed. Run: pip install jsonschema")
        sys.exit(1)
    with open(SCHEMAS[name], encoding="utf-8") as f:
        return jsonschema.Draft7Validator(json.load(f))


def pick_schema(filename: str):
    if filename.endswith("_trace.json"):
        return "trace"
    if filename == "result.json":
        return "result"
    return None


def _fmt_error(e) -> str:
    """Format a jsonschema error, expanding oneOf/anyOf/allOf context.

    The top-level message of a combinator error embeds the entire instance,
    which is unreadable — expand its context sub-errors instead.
    """
    where = ".".join(map(str, e.path)) or "<root>"
    if e.validator in ("oneOf", "anyOf", "allOf") and e.context:
        lines = [f"  {where}: {e.validator} — instance matches none of the alternatives"]
        for c in e.context[:10]:
            cwhere = ".".join(map(str, c.path)) or "<root>"
            lines.append(f"    └ {cwhere}: {c.message[:240]}")
        return "\n".join(lines)
    return f"  {where}: {e.message[:400]}"


def validate_file(path: Path, schema_name: str, validator) -> list[str]:
    """Return a list of validation error messages (empty = valid)."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        return [f"  cannot read/parse: {e}"]

    errors = sorted(validator.iter_errors(data), key=lambda e: list(e.path))
    return [_fmt_error(e) for e in errors]


def main() -> None:
    args = sys.argv[1:]
    if "--file" in args:
        i = args.index("--file")
        path = Path(args[i + 1])
        schema = "result"
        if "--schema" in args:
            j = args.index("--schema")
            schema = args[j + 1]
        if schema not in SCHEMAS:
            _emit(f"Unknown schema '{schema}'. Choose from: {', '.join(SCHEMAS)}")
            sys.exit(1)
        validator = load_schema(schema)
        _emit(f"Checking {path} against {schema}...")
        errors = validate_file(path, schema, validator)
        if errors:
            for e in errors:
                _emit(e)
            _emit("FAIL")
            sys.exit(1)
        _emit("OK")
        sys.exit(0)

    if not RESULTS_DIR.is_dir():
        _emit(f"No results dir: {RESULTS_DIR}")
        sys.exit(1)

    files = sorted(p for p in RESULTS_DIR.rglob("*.json") if p.is_file())
    if not files:
        _emit("No JSON files found under experiment/results/")
        sys.exit(1)

    validators = {name: load_schema(name) for name in SCHEMAS}
    total = checked = passed = failed = skipped = 0

    for path in files:
        total += 1
        schema = pick_schema(path.name)
        if schema is None:
            skipped += 1
            continue
        checked += 1
        errors = validate_file(path, schema, validators[schema])
        if errors:
            failed += 1
            _emit(f"FAIL {path.relative_to(REPO)}")
            for e in errors[:8]:
                _emit(e)
        else:
            passed += 1

    _emit("")
    _emit(f"Checked {checked} ({passed} passed, {failed} failed), {skipped} skipped, {total} total")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
