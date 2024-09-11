#!/usr/bin/env python3
"""Simulated S3 posture audit from static bucket configuration JSON."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _is_public_principal(stmt: dict) -> bool:
    principal = stmt.get("Principal")
    if principal == "*":
        return True
    if isinstance(principal, dict) and principal.get("AWS") == "*":
        return True
    return False


def _bucket_policy_public_read(policy: dict | None) -> bool:
    if not policy:
        return False
    stmts = policy.get("Statement") or []
    if isinstance(stmts, dict):
        stmts = [stmts]
    for s in stmts:
        if s.get("Effect") != "Allow":
            continue
        actions = s.get("Action")
        alist = [actions] if isinstance(actions, str) else (actions or [])
        alist_l = [str(a).lower() for a in alist]
        if _is_public_principal(s) and any("s3:getobject" in a or a == "s3:*" for a in alist_l):
            return True
    return False


def _policy_grants_account_root_star(policy: dict | None) -> bool:
    if not policy:
        return False
    stmts = policy.get("Statement") or []
    if isinstance(stmts, dict):
        stmts = [stmts]
    for s in stmts:
        if s.get("Effect") != "Allow":
            continue
        principal = s.get("Principal") or {}
        if isinstance(principal, dict):
            aws = principal.get("AWS")
            if aws and isinstance(aws, str) and aws.endswith(":root"):
                acts = s.get("Action")
                alist = [acts] if isinstance(acts, str) else (acts or [])
                if any(str(a).strip() == "s3:*" for a in alist):
                    return True
    return False


def audit(data: dict) -> list[dict]:
    findings: list[dict] = []
    n = 0

    def nid() -> str:
        nonlocal n
        n += 1
        return f"S3-{n:03d}"

    for b in data.get("buckets", []):
        name = b.get("Name", "unknown")
        pab = b.get("PublicAccessBlockConfiguration") or {}
        acl = (b.get("ACL") or "").lower()
        enc = b.get("ServerSideEncryptionConfiguration")
        ver = (b.get("Versioning") or {}).get("Status")
        logging = b.get("Logging") or {}
        policy = b.get("BucketPolicy")

        if acl in ("public-read", "public-read-write") or not all(
            pab.get(k, True) for k in (
                "BlockPublicAcls",
                "IgnorePublicAcls",
                "BlockPublicPolicy",
                "RestrictPublicBuckets",
            )
        ):
            findings.append(
                {
                    "id": nid(),
                    "title": "S3 bucket exposes or allows public access configuration",
                    "severity": "Critical",
                    "resource": f"s3://{name}",
                    "category": "S3",
                    "description": "Public ACLs and/or S3 Block Public Access not fully enabled increases risk of data exposure.",
                    "evidence": {"ACL": b.get("ACL"), "PublicAccessBlockConfiguration": pab},
                    "remediation_hint": "Enable all four Block Public Access settings; remove public ACLs; use CloudFront OAC for public content.",
                }
            )

        if enc is None:
            findings.append(
                {
                    "id": nid(),
                    "title": "Default encryption not configured for bucket",
                    "severity": "High",
                    "resource": f"s3://{name}",
                    "category": "S3",
                    "description": "Objects may be stored without default SSE-S3 or SSE-KMS at rest.",
                    "evidence": {"ServerSideEncryptionConfiguration": enc},
                    "remediation_hint": "Enable default bucket encryption; prefer KMS CMK for sensitive data with key policies.",
                }
            )

        if str(ver).lower() != "enabled":
            findings.append(
                {
                    "id": nid(),
                    "title": "S3 versioning not enabled",
                    "severity": "Medium",
                    "resource": f"s3://{name}",
                    "category": "S3",
                    "description": "Without versioning, accidental deletes and ransomware-style overwrites are harder to recover from.",
                    "evidence": {"Versioning": b.get("Versioning")},
                    "remediation_hint": "Enable versioning on critical buckets; pair with lifecycle rules and MFA delete for sensitive buckets.",
                }
            )

        if not logging.get("LoggingEnabled"):
            findings.append(
                {
                    "id": nid(),
                    "title": "Server access logging not enabled",
                    "severity": "Medium",
                    "resource": f"s3://{name}",
                    "category": "S3",
                    "description": "Bucket-level access logging to a dedicated log bucket aids detection and forensics.",
                    "evidence": {"Logging": logging},
                    "remediation_hint": "Enable server access logging to a centralized logging bucket with tight bucket policy.",
                }
            )

        if _bucket_policy_public_read(policy):
            findings.append(
                {
                    "id": nid(),
                    "title": "Bucket policy allows anonymous or public object access",
                    "severity": "Critical",
                    "resource": f"s3://{name}",
                    "category": "S3",
                    "description": "A bucket policy statement grants GetObject (or s3:*) to a public principal.",
                    "evidence": {"BucketPolicy": policy},
                    "remediation_hint": "Remove Principal *; use OAI/OAC, signed URLs, or authenticated viewers only.",
                }
            )
        elif _policy_grants_account_root_star(policy):
            findings.append(
                {
                    "id": nid(),
                    "title": "Overly broad bucket policy (account root with s3:*)",
                    "severity": "High",
                    "resource": f"s3://{name}",
                    "category": "S3",
                    "description": "Granting s3:* to account root bypasses normal IAM boundary discipline and is hard to audit.",
                    "evidence": {"note": "Principal :root with s3:* detected"},
                    "remediation_hint": "Replace with roles, explicit ARNs, and condition keys (aws:PrincipalArn, vpc SourceIp).",
                }
            )

    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit simulated S3 bucket configs JSON.")
    parser.add_argument("input_path", help="Path to s3_bucket_configs.json")
    parser.add_argument("-o", "--output", help="Write findings JSON to this path")
    args = parser.parse_args()

    with open(args.input_path, encoding="utf-8") as f:
        data = json.load(f)

    findings = audit(data)
    out = {
        "scan_type": "s3",
        "generated_at": _now_iso(),
        "source_file": args.input_path,
        "findings": findings,
        "summary": {
            "total": len(findings),
            "by_severity": {
                s: sum(1 for x in findings if x["severity"] == s)
                for s in ("Critical", "High", "Medium", "Low")
            },
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
