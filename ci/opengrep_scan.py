#!/usr/bin/env python3
"""SAST with Opengrep: pinned binary + pinned community rules, security-category findings only.

Usage: opengrep_scan.py SRC_DIR OUT_JSON [--baseline-commit SHA] [--exclude PATTERN ...] [--markdown OUT_MD]
                        [--semgrep-json OUT_JSON]
Writes OUT_JSON (filtered results), optionally a Markdown summary, and prints a one-line summary. Stdlib only.
--semgrep-json also writes the security findings in Semgrep's native report shape, which is what
DefectDojo's "Semgrep JSON Report" importer reads (OUT_JSON is a custom summary it cannot parse).
Copied from datopian/dx-helm-sse-dev ci/opengrep_scan.py; keep the two in sync.
"""
import argparse
import collections
import hashlib
import io
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

OPENGREP_VERSION = "v1.31.0"
OPENGREP_BUILDS = {  # platform.machine() -> (release asset, sha256)
    "x86_64": ("opengrep_manylinux_x86", "dbbe3c2058dbe600c449a8ba22ea79a1643a6660658400090d0323a8d0d31147"),
    "aarch64": ("opengrep_manylinux_aarch64", "2b713a29a00237f85408b83002fc111db5b94c7fa8d263f0a93184a960655d9d"),
}
RULES_COMMIT = "f1d2b562b414783763fd02a6ed2736eaed622efa"
RULE_DIRS = ["python", "javascript", "typescript", "html", "generic/secrets"]
# Rule sets for frameworks CKAN does not use: CKAN is Flask with browser-side
# jQuery, so Django template/view rules and Node server (Express, Sequelize)
# rules only produce false positives. The Flask, jQuery and SQLAlchemy sets stay.
EXCLUDED_RULE_SETS = ["python/django", "javascript/express", "javascript/sequelize"]
DEFAULT_EXCLUDES = ["*.min.js", "*.map", "vendor", "node_modules", "tests", "test", "webassets", "i18n"]


def fetch(url):
    with urllib.request.urlopen(url, timeout=120) as r:
        return r.read()


def get_opengrep(workdir):
    path = os.path.join(workdir, "opengrep")
    arch = platform.machine()
    if arch not in OPENGREP_BUILDS:
        sys.exit(f"no pinned opengrep build for {arch}")
    asset, expected = OPENGREP_BUILDS[arch]
    data = fetch(f"https://github.com/opengrep/opengrep/releases/download/{OPENGREP_VERSION}/{asset}")
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected:
        sys.exit(f"opengrep checksum mismatch: {digest}")
    with open(path, "wb") as f:
        f.write(data)
    os.chmod(path, 0o755)
    return path


def get_rules(workdir):
    data = fetch(f"https://codeload.github.com/opengrep/opengrep-rules/tar.gz/{RULES_COMMIT}")
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        if hasattr(tarfile, "data_filter"):
            tar.extractall(workdir, filter="data")
        else:
            for m in tar.getmembers():
                if m.name.startswith("/") or ".." in m.name.split("/") or not (m.isfile() or m.isdir()):
                    sys.exit(f"unsafe path in rules archive: {m.name}")
            tar.extractall(workdir)
    root = os.path.join(workdir, f"opengrep-rules-{RULES_COMMIT}")
    for rule_set in EXCLUDED_RULE_SETS:
        shutil.rmtree(os.path.join(root, rule_set))
    return [os.path.join(root, d) for d in RULE_DIRS]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("src")
    ap.add_argument("out")
    ap.add_argument("--baseline-commit")
    ap.add_argument("--exclude", action="append", default=[])
    ap.add_argument("--markdown")
    ap.add_argument("--semgrep-json")
    a = ap.parse_args()

    with tempfile.TemporaryDirectory() as work:
        binary = get_opengrep(work)
        cmd = [binary, "scan", "--json", "--quiet", "--timeout", "30", "--max-target-bytes", "2000000"]
        for cfg in get_rules(work):
            cmd += ["--config", cfg]
        for pat in DEFAULT_EXCLUDES + a.exclude:
            cmd += ["--exclude", pat]
        if a.baseline_commit:
            cmd += ["--baseline-commit", a.baseline_commit]
        raw = os.path.join(work, "raw.json")
        cmd += ["--output", raw, "."]
        rc = subprocess.run(cmd, cwd=a.src).returncode
        if rc not in (0, 1) or not os.path.exists(raw):
            sys.exit(f"opengrep failed (rc={rc})")
        data = json.load(open(raw))

    results = [r for r in data["results"] if (r["extra"].get("metadata") or {}).get("category") == "security"]
    if a.semgrep_json:
        with open(a.semgrep_json, "w") as f:
            json.dump({"version": OPENGREP_VERSION.lstrip("v"), "results": results, "errors": []}, f)
    sev = collections.Counter(r["extra"]["severity"] for r in results)
    out = {
        "tool": f"opengrep {OPENGREP_VERSION}",
        "rules_commit": RULES_COMMIT,
        "baseline_commit": a.baseline_commit,
        "files_scanned": len(data["paths"]["scanned"]),
        "parse_errors": len(data["errors"]),
        "counts": {"ERROR": sev.get("ERROR", 0), "WARNING": sev.get("WARNING", 0), "INFO": sev.get("INFO", 0)},
        "results": [
            {
                "rule": r["check_id"],
                "severity": r["extra"]["severity"],
                "path": r["path"],
                "line": r["start"]["line"],
                "code": r["extra"].get("lines", "").strip()[:300],
                "message": r["extra"].get("message", "")[:500],
                "cwe": (r["extra"].get("metadata") or {}).get("cwe"),
            }
            for r in results
        ],
    }
    with open(a.out, "w") as f:
        json.dump(out, f, indent=1)
    c = out["counts"]
    if a.markdown:
        write_markdown(out, a.markdown)
    print(f"SAST: {len(results)} security findings (error {c['ERROR']}, warning {c['WARNING']}, info {c['INFO']}) "
          f"in {out['files_scanned']} files, {out['parse_errors']} parse errors")


def write_markdown(out, path, limit=25):
    c = out["counts"]
    scope = f"new since `{out['baseline_commit'][:7]}`" if out["baseline_commit"] else "whole tree"
    lines = [
        f"**{len(out['results'])} security findings** ({scope}): "
        f"{c['ERROR']} error, {c['WARNING']} warning, {c['INFO']} info. "
        f"{out['tool']}, rules `{out['rules_commit'][:7]}`, {out['files_scanned']} files scanned.",
        "",
    ]
    order = {"ERROR": 0, "WARNING": 1, "INFO": 2}
    rows = sorted(out["results"], key=lambda r: (order.get(r["severity"], 3), r["path"], r["line"]))
    if rows:
        lines += ["| Severity | Rule | Location |", "|---|---|---|"]
        for r in rows[:limit]:
            lines.append(f"| {r['severity']} | `{r['rule'].split('.')[-1]}` | `{r['path']}:{r['line']}` |")
        if len(rows) > limit:
            lines.append(f"\n_...and {len(rows) - limit} more in the full report._")
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
