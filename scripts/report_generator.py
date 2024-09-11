#!/usr/bin/env python3
"""Merge auditor JSON outputs into assessment_report.md and cloudtrail_incident_timeline.md."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from datetime import datetime, timezone

SEVERITY_ORDER = ("Critical", "High", "Medium", "Low")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _esc(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def _collect_findings(iam: dict, s3: dict, sg: dict, ct: dict) -> list[dict]:
    out = []
    for chunk, label in (
        (iam.get("findings") or [], "IAM"),
        (s3.get("findings") or [], "S3"),
        (sg.get("findings") or [], "SG"),
        (ct.get("findings") or [], "CloudTrail"),
    ):
        for f in chunk:
            row = dict(f)
            row["_domain"] = label
            out.append(row)
    return out


def _risk_matrix_counts(findings: list[dict]) -> dict[tuple[str, str], int]:
    """Simple heuristic: Critical/High -> High impact; Medium/Low -> lower."""
    grid: dict[tuple[str, str], int] = defaultdict(int)
    for f in findings:
        sev = f.get("severity", "Low")
        impact = "High" if sev in ("Critical", "High") else "Medium"
        likelihood = "High" if sev == "Critical" else ("Medium" if sev == "High" else "Low")
        grid[(likelihood, impact)] += 1
    return grid


def build_assessment_report(
    findings: list[dict],
    generated_at: str,
    grid: dict[tuple[str, str], int],
) -> str:
    crit = sum(1 for f in findings if f.get("severity") == "Critical")
    high = sum(1 for f in findings if f.get("severity") == "High")

    lines = [
        "# AWS Cloud Security Assessment Report",
        "",
        f"**Assessment artifact generated:** `{generated_at}`  ",
        "**Scope:** Simulated static configuration and log export (`environment/*.json`) — no live AWS account required.",
        "",
        "## Executive summary",
        "",
        "This report summarizes control gaps identified through a **design review** of IAM and data-plane configuration, **automated policy checks** over JSON exports, and **CloudTrail-style log analysis** for detective signals. The simulated account shows a **material concentration of critical issues** in identity trust, network exposure, and S3 public-access posture, compounded by **log tampering and suspicious role assumption patterns** in the sample timeline.",
        "",
        f"- **Critical findings:** {crit}",
        f"- **High findings:** {high}",
        f"- **Total findings:** {len(findings)}",
        "",
        "Overall, the organization would be exposed to **credential theft leading to data exfiltration**, **lateral movement via over-permissive security groups**, and **impaired forensics** if logging is interrupted. Remediation should prioritize **stopping public and root-level risk**, then **tightening cross-account trust**, then **sustained detective controls** (immutable audit trail, alerting).",
        "",
        "## Findings",
        "",
        "| ID | Domain | Severity | Title | Affected resource |",
        "|----|--------|----------|-------|-------------------|",
    ]

    sorted_f = sorted(
        findings,
        key=lambda x: (SEVERITY_ORDER.index(x.get("severity", "Low")), x.get("id", "")),
    )
    for f in sorted_f:
        lines.append(
            f"| {_esc(str(f.get('id','')))} | {_esc(str(f.get('_domain','')))} | "
            f"{_esc(str(f.get('severity','')))} | {_esc(str(f.get('title','')))} | "
            f"{_esc(str(f.get('resource','')))} |"
        )

    lines.extend(
        [
            "",
            "### Detailed findings",
            "",
        ]
    )

    for f in sorted_f:
        lines.extend(
            [
                f"#### {f.get('id')} — {f.get('title')}",
                "",
                f"- **Severity:** {f.get('severity')}",
                f"- **Domain:** {f.get('_domain')}",
                f"- **Resource:** `{f.get('resource')}`",
                "",
                f"**Description:** {f.get('description','')}",
                "",
                f"**Evidence (excerpt):** `{json.dumps(f.get('evidence'), default=str)[:400]}{'...' if len(json.dumps(f.get('evidence'), default=str)) > 400 else ''}`",
                "",
                f"**Remediation (summary):** {f.get('remediation_hint','')}",
                "",
                "---",
                "",
            ]
        )

    lines.extend(
        [
            "## Risk matrix (likelihood × impact)",
            "",
            "Counts are **heuristic buckets** derived from finding severity (portfolio-friendly, not actuarial).",
            "",
            "|  | Impact: High | Impact: Medium |",
            "|--|--------------|----------------|",
            f"| **Likelihood: High** | {grid.get(('High','High'), 0)} | {grid.get(('High','Medium'), 0)} |",
            f"| **Likelihood: Medium** | {grid.get(('Medium','High'), 0)} | {grid.get(('Medium','Medium'), 0)} |",
            f"| **Likelihood: Low** | {grid.get(('Low','High'), 0)} | {grid.get(('Low','Medium'), 0)} |",
            "",
            "## Prioritized remediation roadmap",
            "",
            "1. **Immediate (0–7 days):** Remove internet-exposed administrative ports; lock down public S3 buckets and Block Public Access; disable root API/console use except break-glass; restore and protect CloudTrail (immutable storage, alerts on `StopLogging`).",
            "2. **Short term (1–4 weeks):** Replace wildcard IAM; remove long-lived superuser on application users; add `sts:ExternalId` and source constraints on vendor roles; enforce MFA for console users.",
            "3. **Medium term (1–3 months):** SCP guardrails, AWS Config rules for S3 public access and SG open ports, centralized logging with Athena queries, quarterly access reviews and IAM Access Analyzer workflows.",
            "",
            "## Methodology note",
            "",
            "Artifacts were produced by local Python scanners (`scripts/*.py`) over **synthetic JSON** meant to mirror AWS CLI/config exports. This demonstrates **audit workflow and risk framing** rather than live environment discovery.",
            "",
        ]
    )

    return "\n".join(lines)


def build_timeline_md(ct_data: dict) -> str:
    timeline = ct_data.get("timeline") or []
    interesting = [
        e
        for e in timeline
        if e.get("risk_note")
        or e.get("eventName")
        in (
            "StopLogging",
            "PutBucketPolicy",
            "AssumeRole",
            "ConsoleLogin",
            "GetObject",
            "CreateAccessKey",
            "DeleteTrail",
        )
    ]

    lines = [
        "# CloudTrail incident timeline (simulated)",
        "",
        "This narrative is derived from the **synthetic** `environment/cloudtrail_logs.json` sample. It is written to mirror how an assessor would **chain events** during an interview walkthrough: reconnaissance noise, privilege/use of roles, defense evasion, and attempted access to sensitive objects.",
        "",
        "## Storyline (analyst view)",
        "",
        "**Phase A — Access and reconnaissance.** Contractors and standard users sign in from mixed addresses. Several sessions report **console login without MFA**, lowering the bar for session theft. IAM APIs (`ListUsers`, `GetUserPolicy`, `SimulatePrincipalPolicy`) show **repeated AccessDenied** bursts consistent with **enumeration** or tooling probing effective permissions.",
        "",
        "**Phase B — Role assumption from unusual networks.** `AssumeRole` appears from **IPs outside the simulated corporate ranges**, including activity against a **cross-account vendor role**. That pattern often indicates **stolen long-lived credentials** or a **confused-deputy** trust that is too loose for the actual caller.",
        "",
        "**Phase C — Defense evasion.** A **`StopLogging`** event against the organization trail is a **critical anti-forensics** signal. Even if logging is restarted, the window may have hidden follow-on actions and should trigger **incident response** in a real account.",
        "",
        "**Phase D — Data exposure attempt.** **`PutBucketPolicy`** with a **wildcard principal** on a corporate bucket aligns with **making objects readable to the internet**. Subsequent **`GetObject` AccessDenied** bursts against a finance bucket suggest **attempted lateral movement to higher-sensitivity data** that IAM thankfully blocked.",
        "",
        "**Phase E — Persistence attempts (blocked).** Rapid **`CreateAccessKey` / `AttachUserPolicy` denials** under the same role session resemble **privilege escalation** attempts that failed due to residual least-privilege on the role — a good outcome, but the attempt still matters for detection tuning.",
        "",
        "## Flagged chronological events",
        "",
        "| Time (UTC) | Event | Source IP | Principal | Notes |",
        "|------------|-------|-----------|-----------|-------|",
    ]

    for e in interesting:
        note = e.get("risk_note") or ""
        lines.append(
            f"| {e.get('eventTime','')} | {e.get('eventName','')} | {e.get('sourceIPAddress','')} | "
            f"{_esc(str(e.get('principal','')))} | {_esc(note)} |"
        )

    lines.extend(
        [
            "",
            "## What to say in an interview",
            "",
            "- **Detection:** You would tune alerts for `StopLogging`, `PutBucketPolicy` with public principals, and bursts of `AccessDenied` grouped by principal.",
            "- **Response:** Preserve trail artifacts in immutable storage, pivot on `AssumeRole` session names and access keys, and scope blast radius via S3 policies and SCPs.",
            "- **Prevention:** MFA enforcement, ExternalId on vendor trusts, no admin ports `0.0.0.0/0`, and S3 Block Public Access org-wide.",
            "",
        ]
    )

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate Markdown reports from auditor JSON outputs.")
    parser.add_argument("--iam", default="reports/iam_findings.json")
    parser.add_argument("--s3", default="reports/s3_findings.json")
    parser.add_argument("--sg", default="reports/sg_findings.json")
    parser.add_argument("--cloudtrail", default="reports/cloudtrail_analysis.json")
    parser.add_argument("--out-dir", default="reports")
    args = parser.parse_args()

    iam = _load(args.iam)
    s3 = _load(args.s3)
    sg = _load(args.sg)
    ct = _load(args.cloudtrail)

    generated = _now_iso()
    findings = _collect_findings(iam, s3, sg, ct)
    grid = _risk_matrix_counts(findings)

    assessment_path = f"{args.out_dir.rstrip('/')}/assessment_report.md"
    timeline_path = f"{args.out_dir.rstrip('/')}/cloudtrail_incident_timeline.md"

    with open(assessment_path, "w", encoding="utf-8") as af:
        af.write(build_assessment_report(findings, generated, grid))
    with open(timeline_path, "w", encoding="utf-8") as tf:
        tf.write(build_timeline_md(ct))

    print(f"Wrote {assessment_path}")
    print(f"Wrote {timeline_path}")


if __name__ == "__main__":
    main()
