#!/usr/bin/env python3
"""Simulated CloudTrail log analysis — pattern matching and simple time windows (no AWS API)."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone


def _parse_time(s: str) -> datetime:
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _identity_label(ui: dict) -> str:
    t = ui.get("type", "Unknown")
    if t == "IAMUser":
        return f"IAMUser:{ui.get('userName', '')}"
    if t == "Root":
        return "Root"
    if t == "AssumedRole":
        return ui.get("arn") or "AssumedRole"
    return t


def _ip_in_trusted(ip: str, cidrs: list[str]) -> bool:
    """Very small RFC-style check: exact prefix match for /24 and /32 style lists in portfolio data."""
    if not ip or ip.startswith("10.") or ip.startswith("172.16."):
        return True  # treat private as internal / non-suspicious for this simulation
    if ip.startswith("192.168."):
        return True
    for c in cidrs:
        if "/" not in c:
            continue
        base, _, mask_s = c.partition("/")
        try:
            mask = int(mask_s)
        except ValueError:
            continue
        if mask == 32 and ip == base:
            return True
        if mask == 24:
            parts = ip.split(".")
            bparts = base.split(".")
            if len(parts) == 4 and len(bparts) == 4 and parts[:3] == bparts[:3]:
                return True
    return False


def analyze(data: dict) -> tuple[list[dict], list[dict]]:
    """Returns (findings, timeline_events)."""
    meta = data.get("metadata") or {}
    trusted = meta.get("trusted_corporate_cidrs") or []
    records = data.get("Records") or []

    findings: list[dict] = []
    timeline: list[dict] = []
    n = 0

    def fid() -> str:
        nonlocal n
        n += 1
        return f"CT-{n:03d}"

    denied_by_principal: dict[str, list[datetime]] = defaultdict(list)

    sorted_recs = sorted(records, key=lambda r: r.get("eventTime", ""))

    for rec in sorted_recs:
        et = rec.get("eventTime", "")
        en = rec.get("eventName", "")
        ip = rec.get("sourceIPAddress") or ""
        ui = rec.get("userIdentity") or {}
        err = rec.get("errorCode")

        tl_entry = {
            "eventTime": et,
            "eventName": en,
            "sourceIPAddress": ip,
            "principal": _identity_label(ui),
            "errorCode": err,
            "risk_note": None,
        }

        if ui.get("type") == "Root":
            findings.append(
                {
                    "id": fid(),
                    "title": "Root account API usage detected",
                    "severity": "Critical",
                    "resource": "account root",
                    "category": "CloudTrail",
                    "description": "Root should be locked away; any interactive or API use is high risk.",
                    "evidence": {"eventName": en, "eventTime": et, "sourceIPAddress": ip},
                    "remediation_hint": "Remove root access keys; enable MFA on root; use break-glass procedures only.",
                }
            )
            tl_entry["risk_note"] = "Root activity — break-glass policy violation risk"

        if en == "ConsoleLogin":
            mfa = (rec.get("additionalEventData") or {}).get("MFAUsed")
            if mfa == "No":
                findings.append(
                    {
                        "id": fid(),
                        "title": "Console login without MFA",
                        "severity": "High",
                        "resource": _identity_label(ui),
                        "category": "CloudTrail",
                        "description": "Successful console authentication reported MFAUsed=No.",
                        "evidence": {"eventTime": et, "sourceIPAddress": ip},
                        "remediation_hint": "Enforce MFA via IAM policy or Identity Center; deny console without MFA.",
                    }
                )
                tl_entry["risk_note"] = "Console login without MFA"

        if en == "AssumeRole" and not _ip_in_trusted(ip, trusted):
            if not ip.startswith("10.") and not ip.startswith("192.168."):
                findings.append(
                    {
                        "id": fid(),
                        "title": "AssumeRole from non-corporate source IP",
                        "severity": "High",
                        "resource": _identity_label(ui),
                        "category": "CloudTrail",
                        "description": f"Role assumption from IP {ip} outside simulated trusted corporate ranges.",
                        "evidence": {"eventTime": et, "requestParameters": rec.get("requestParameters")},
                        "remediation_hint": "Tighten role trust with SourceIp / vpc conditions; alert on geo anomalies.",
                    }
                )
                tl_entry["risk_note"] = "Cross-principal role assumption from unusual IP"

        if en in ("StopLogging", "DeleteTrail"):
            outcome = "succeeded" if not err else f"returned {err}"
            sev = "Critical" if en == "StopLogging" and not err else ("High" if err else "Critical")
            findings.append(
                {
                    "id": fid(),
                    "title": f"CloudTrail tampering indicator: {en} ({outcome})",
                    "severity": sev,
                    "resource": rec.get("requestParameters", {}).get("name", "trail"),
                    "category": "CloudTrail",
                    "description": "Logging pipeline modification (or attempted modification) is a common defense-evasion technique; successful StopLogging is especially severe.",
                    "evidence": {"eventTime": et, "principal": _identity_label(ui), "sourceIPAddress": ip, "errorCode": err},
                    "remediation_hint": "Restrict cloudtrail:* to security admin role; immutable S3 + SNS alerts on StopLogging.",
                }
            )
            tl_entry["risk_note"] = "Audit log tampering / evasion"

        if en == "PutBucketPolicy":
            rp = rec.get("requestParameters") or {}
            pol = str(rp.get("policy", ""))
            if "Principal" in pol and "*" in pol:
                findings.append(
                    {
                        "id": fid(),
                        "title": "PutBucketPolicy altering public or wildcard principal",
                        "severity": "Critical",
                        "resource": rp.get("bucketName", "unknown-bucket"),
                        "category": "CloudTrail",
                        "description": "Bucket policy update referencing wildcard principal — often public-read misconfiguration.",
                        "evidence": {"eventTime": et, "principal": _identity_label(ui)},
                        "remediation_hint": "Revert policy; enable Block Public Access; investigate principal that issued change.",
                    }
                )
                tl_entry["risk_note"] = "Bucket policy change toward public access"

        if err == "AccessDenied":
            key = _identity_label(ui)
            denied_by_principal[key].append(_parse_time(et))

        timeline.append(tl_entry)

    # Burst detection: 4+ AccessDenied within 120 seconds per principal
    window = timedelta(seconds=120)
    for principal, times in denied_by_principal.items():
        times.sort()
        for i, start in enumerate(times):
            chunk = [t for t in times if start <= t <= start + window]
            if len(chunk) >= 4:
                findings.append(
                    {
                        "id": fid(),
                        "title": "Burst of AccessDenied errors (possible enumeration)",
                        "severity": "Medium",
                        "resource": principal,
                        "category": "CloudTrail",
                        "description": f"Observed {len(chunk)} denied API calls within ~2 minutes — often reconnaissance.",
                        "evidence": {"window_start": start.isoformat(), "count": len(chunk)},
                        "remediation_hint": "Correlate with GuardDuty; apply SCP denies for s3:ListAllMyBuckets at perimeter if abuse.",
                    }
                )
                break

    return findings, timeline


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze simulated cloudtrail_logs.json")
    parser.add_argument("input_path", help="Path to cloudtrail_logs.json")
    parser.add_argument("-o", "--output", help="Write analysis JSON (findings + timeline) to this path")
    args = parser.parse_args()

    with open(args.input_path, encoding="utf-8") as f:
        data = json.load(f)

    findings, timeline = analyze(data)
    out = {
        "scan_type": "cloudtrail",
        "generated_at": _now_iso(),
        "source_file": args.input_path,
        "findings": findings,
        "timeline": timeline,
        "summary": {
            "total_findings": len(findings),
            "by_severity": {
                s: sum(1 for x in findings if x["severity"] == s)
                for s in ("Critical", "High", "Medium", "Low")
            },
            "timeline_entries": len(timeline),
        },
    }
    text = json.dumps(out, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as wf:
            wf.write(text)
    else:
        print(text)


if __name__ == "__main__":
    main()
