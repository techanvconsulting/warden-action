#!/usr/bin/env python3
"""
Bridge Warden AI security-review results into the Warden platform.

Reads the action's results JSON (the ``results-file`` output) and pushes the
findings to a Warden instance through the CI ingest API so they appear in the
dashboard alongside the rest of the scanner fleet:

    POST /api/ci/scan        (CI-TOKEN header) -> { scanId, scanUrl, ... }
    POST /api/ci/finding     { scanId, findings[], strategy }
    PUT  /api/ci/scan/{id}   { status, description }

Pure stdlib (urllib) — no extra dependencies. Safe no-op when WARDEN_URL or
WARDEN_TOKEN is unset, so it can be wired in unconditionally.

Environment:
    WARDEN_URL          base URL of the Warden API (e.g. https://warden.example.com)
    WARDEN_TOKEN        a Warden CI access token
    GITHUB_REPOSITORY   owner/repo (provided by GitHub Actions)
    PR_NUMBER           pull-request number
    GITHUB_SHA / SHA    commit SHA
    GITHUB_HEAD_REF     PR source branch
    GITHUB_BASE_REF     PR target branch
    GITHUB_SERVER_URL   default https://github.com
    GITHUB_RUN_ID       run id (for the job URL)

Usage: warden_upload.py <results.json>
"""

import hashlib
import json
import os
import sys
import urllib.error
import urllib.request

SEVERITY_MAP = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "MODERATE": "Medium",
    "LOW": "Low",
    "INFO": "Info",
    "INFORMATIONAL": "Info",
}


def _env(*names, default=""):
    for name in names:
        value = os.environ.get(name)
        if value:
            return value
    return default


def _request(method, url, token, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    req.add_header("CI-TOKEN", token)
    with urllib.request.urlopen(req, timeout=60) as resp:
        raw = resp.read().decode()
        return json.loads(raw) if raw else {}


def _first_sentence(text, limit=120):
    text = " ".join((text or "").split())
    if not text:
        return "AI security finding"
    for end in (". ", "! ", "? "):
        idx = text.find(end)
        if 0 < idx < limit:
            return text[: idx + 1].strip()
    return text[:limit].strip()


def _map_finding(raw):
    file_path = raw.get("file") or raw.get("file_path") or raw.get("path") or ""
    line = raw.get("line") or raw.get("line_number") or raw.get("start_line")
    description = raw.get("description") or raw.get("message") or ""
    exploit = raw.get("exploit_scenario") or raw.get("impact") or ""
    full_desc = description
    if exploit:
        full_desc = f"{description}\n\n**Exploit scenario:** {exploit}".strip()
    severity = SEVERITY_MAP.get(str(raw.get("severity", "")).upper(), "Medium")
    cwe = raw.get("cwe") or raw.get("rule_id") or raw.get("ruleId")

    identity_seed = f"{file_path}:{line}:{raw.get('title') or _first_sentence(description)}"
    identity = "warden-ai:" + hashlib.sha1(identity_seed.encode()).hexdigest()[:16]

    finding = {
        "identity": identity,
        "name": raw.get("title") or _first_sentence(description),
        "description": full_desc or "AI security finding",
        "severity": severity,
        "category": raw.get("category") or "ai-security-review",
        "recommendation": raw.get("recommendation") or raw.get("remediation") or None,
        "ruleId": str(cwe) if cwe else None,
    }
    if file_path:
        loc = {"path": file_path}
        if isinstance(line, int) and line > 0:
            loc["startLine"] = line
            loc["endLine"] = line
        finding["location"] = loc
    return {k: v for k, v in finding.items() if v is not None}


def main():
    if len(sys.argv) < 2:
        print("usage: warden_upload.py <results.json>", file=sys.stderr)
        return 2

    warden_url = _env("WARDEN_URL").rstrip("/")
    token = _env("WARDEN_TOKEN")
    if not warden_url or not token:
        print("[warden] WARDEN_URL / WARDEN_TOKEN not set — skipping platform upload.")
        return 0

    results_path = sys.argv[1]
    if not os.path.isfile(results_path):
        print(f"[warden] results file not found: {results_path} — skipping.")
        return 0

    with open(results_path) as fh:
        results = json.load(fh)
    raw_findings = results.get("findings", [])

    repo = _env("GITHUB_REPOSITORY", default="unknown/repo")
    server = _env("GITHUB_SERVER_URL", default="https://github.com").rstrip("/")
    pr_number = _env("PR_NUMBER")
    sha = _env("GITHUB_SHA", "SHA", default="")
    head = _env("GITHUB_HEAD_REF", default="")
    base = _env("GITHUB_BASE_REF", default="")
    run_id = _env("GITHUB_RUN_ID")

    scan_request = {
        "source": "GitHub",
        "repoId": repo,
        "repoUrl": f"{server}/{repo}",
        "repoName": repo.split("/")[-1],
        "gitAction": "MergeRequest" if pr_number else "CommitBranch",
        "scanTitle": "Warden AI Security Review",
        "commitBranch": head or base or "main",
        "commitHash": sha,
        "scanner": "warden-ai",
        "type": "Sast",
        "isDefault": not bool(pr_number),
    }
    if pr_number:
        scan_request["mergeRequestId"] = str(pr_number)
        scan_request["targetBranch"] = base
    if run_id:
        scan_request["jobUrl"] = f"{server}/{repo}/actions/runs/{run_id}"

    try:
        scan = _request("POST", f"{warden_url}/api/ci/scan", token, scan_request)
        scan_id = scan.get("scanId")
        if not scan_id:
            print(f"[warden] unexpected scan response: {scan}", file=sys.stderr)
            return 1
        print(f"[warden] scan {scan_id} created for {repo}")

        findings = [_map_finding(f) for f in raw_findings]
        _request(
            "POST",
            f"{warden_url}/api/ci/finding",
            token,
            {"scanId": scan_id, "findings": findings, "strategy": "AllFiles"},
        )
        print(f"[warden] uploaded {len(findings)} finding(s)")

        _request("PUT", f"{warden_url}/api/ci/scan/{scan_id}", token, {"status": "Completed"})
        print("[warden] scan completed")
        return 0
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode()[:400]
        print(f"[warden] upload failed: HTTP {exc.code} {detail}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 - surface any failure, never block the action
        print(f"[warden] upload failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
