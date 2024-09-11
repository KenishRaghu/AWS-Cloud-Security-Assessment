#!/usr/bin/env python3
"""Simulated IAM policy audit — reads static JSON, emits structured findings (no AWS API calls)."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from datetime import datetime, timezone

SENSITIVE_ACTION_PREFIXES = (
    "iam:",
    "sts:AssumeRole",
    "organizations:",
    "account:",
)
MFA_CONDITION_KEYS = (
    "aws:MultiFactorAuthPresent",
    "aws:MultiFactorAuthAge",
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _actions(stmt: dict) -> list[str]:
    a = stmt.get("Action")
    if a is None:
        return []
    if isinstance(a, str):
        return [a]
    return list(a)


def _resources(stmt: dict) -> list[str]:
    r = stmt.get("Resource")
    if r is None:
        return []
    if isinstance(r, str):
        return [r]
    return list(r)


def _has_mfa_condition(stmt: dict) -> bool:
    cond = stmt.get("Condition") or {}
    if not isinstance(cond, dict):
        return False
    for op, inner in cond.items():
        if not isinstance(inner, dict):
            continue
        for key in inner:
            if key in MFA_CONDITION_KEYS or "MultiFactorAuth" in key:
                return True
    return False


def _statement_wildcard_issue(stmt: dict) -> tuple[bool, str | None]:
    actions = _actions(stmt)
    resources = _resources(stmt)
    if stmt.get("Effect") != "Allow":
        return False, None
    if "*" in actions or any(a.strip() == "*" for a in actions):
        return True, "Statement allows Action *"
    if "*" in resources:
        return True, "Statement allows Resource *"
    return False, None


def _sensitive_without_mfa(stmt: dict) -> bool:
    if stmt.get("Effect") != "Allow":
        return False
    if _has_mfa_condition(stmt):
        return False
    for act in _actions(stmt):
        act_l = act.lower()
        if act_l == "*" or any(act_l.startswith(p.lower()) for p in SENSITIVE_ACTION_PREFIXES):
            return True
    return False


def _policy_doc_statements(doc: dict | None) -> list[dict]:
    if not doc or not isinstance(doc, dict):
        return []
    stmts = doc.get("Statement")
    if stmts is None:
        return []
    if isinstance(stmts, dict):
        return [stmts]
    return list(stmts)


def _looks_like_access_key_id(blob: str) -> bool:
    i = blob.find("AKIA")
    if i < 0 or len(blob) < i + 20:
        return False
    tail = blob[i + 4 : i + 20]
    return len(tail) == 16 and tail.isalnum()


def _scan_inline_credential_blob(blob: str) -> list[str]:
    hits = []
    if _looks_like_access_key_id(blob):
        hits.append("Possible AWS access key id pattern in policy text")
    low = blob.lower()
    if "secret_key=" in low or "aws_secret_access_key" in low:
        hits.append("Possible secret key reference in policy text")
    return hits


def audit(data: dict) -> list[dict]:
    findings: list[dict] = []
    fid = 0

    def next_id(prefix: str) -> str:
        nonlocal fid
        fid += 1
        return f"{prefix}-{fid:03d}"

    # Managed policies
    for pol in data.get("managed_policies", []):
        pname = pol.get("PolicyName", "unknown")
        parn = pol.get("PolicyArn", pname)
        doc = (pol.get("DefaultVersion") or {}).get("Document") or {}
        raw = json.dumps(pol, default=str)

        for stmt in _policy_doc_statements(doc):
            bad, reason = _statement_wildcard_issue(stmt)
            if bad:
                findings.append(
                    {
                        "id": next_id("IAM"),
                        "title": "Overly permissive IAM policy statement",
                        "severity": "Critical",
                        "resource": parn,
                        "category": "IAM",
                        "description": f"Managed policy '{pname}' contains a broad Allow: {reason}.",
                        "evidence": {"policy_name": pname, "statement_sid": stmt.get("Sid")},
                        "remediation_hint": "Replace * with explicit actions/resources; split duties across roles.",
                    }
                )
            if _sensitive_without_mfa(stmt):
                findings.append(
                    {
                        "id": next_id("IAM"),
                        "title": "Sensitive IAM/API actions without MFA condition",
                        "severity": "High",
                        "resource": parn,
                        "category": "IAM",
                        "description": f"Policy '{pname}' grants sensitive capabilities without aws:MultiFactorAuthPresent (or similar).",
                        "evidence": {"policy_name": pname, "actions_sample": _actions(stmt)[:5]},
                        "remediation_hint": "Add MFA conditions for human principals; use roles for automation with externalId.",
                    }
                )

        for hit in _scan_inline_credential_blob(raw):
            findings.append(
                {
                    "id": next_id("IAM"),
                    "title": "Simulated inline credential material in policy export",
                    "severity": "Critical",
                    "resource": parn,
                    "category": "IAM",
                    "description": hit,
                    "evidence": {"policy_name": pname},
                    "remediation_hint": "Rotate any exposed keys; store secrets in Secrets Manager; use IAM Roles for workloads.",
                }
            )

        # Unused / stale permissions heuristic
        for stmt in _policy_doc_statements(doc):
            for res in _resources(stmt):
                if "deprecated" in res.lower() and stmt.get("Effect") == "Allow":
                    findings.append(
                        {
                            "id": next_id("IAM"),
                            "title": "Potentially unused or stale IAM permissions",
                            "severity": "Low",
                            "resource": parn,
                            "category": "IAM",
                            "description": f"Policy '{pname}' still grants access to resources that appear deprecated.",
                            "evidence": {"resource": res},
                            "remediation_hint": "Validate last-access; remove unused statements; use IAM Access Analyzer.",
                        }
                    )

        summ = pol.get("AttachmentSummary") or {}
        users_attached = summ.get("attached_to_users") or []
        if users_attached and any(
            _statement_wildcard_issue(s)[0] for s in _policy_doc_statements(doc)
        ):
            findings.append(
                {
                    "id": next_id("IAM"),
                    "title": "High-risk managed policy attached directly to IAM users",
                    "severity": "High",
                    "resource": parn,
                    "category": "IAM",
                    "description": f"Policy '{pname}' with broad permissions is attached to users {users_attached} instead of roles.",
                    "evidence": {"users": users_attached},
                    "remediation_hint": "Move humans to SSO/roles; attach broad policies only to instance/task roles with trust constraints.",
                }
            )

    # Inline user policies
    for user in data.get("users", []):
        uname = user.get("UserName", "unknown")
        for inline in user.get("InlinePolicies") or []:
            iname = inline.get("PolicyName", "inline")
            doc = inline.get("PolicyDocument") or {}
            for stmt in _policy_doc_statements(doc):
                bad, reason = _statement_wildcard_issue(stmt)
                if bad:
                    findings.append(
                        {
                            "id": next_id("IAM"),
                            "title": "Inline user policy with wildcard Action or Resource",
                            "severity": "High",
                            "resource": f"user/{uname}/{iname}",
                            "category": "IAM",
                            "description": f"User '{uname}' inline policy '{iname}': {reason}.",
                            "evidence": {"user": uname, "inline_policy": iname},
                            "remediation_hint": "Convert to managed policy with review; scope resources to bucket/table ARNs.",
                        }
                    )

    # Users with managed policy attachments (least privilege / hygiene)
    user_policy_map: dict[str, list[str]] = defaultdict(list)
    for pol in data.get("managed_policies", []):
        pname = pol.get("PolicyName")
        for u in (pol.get("AttachmentSummary") or {}).get("attached_to_users") or []:
            user_policy_map[u].append(pname)
    for u, plist in user_policy_map.items():
        if len(plist) >= 2:
            findings.append(
                {
                    "id": next_id("IAM"),
                    "title": "Multiple managed policies attached to a single IAM user",
                    "severity": "Medium",
                    "resource": f"user/{u}",
                    "category": "IAM",
                    "description": "Users with many attached policies are harder to reason about and often indicate long-lived access.",
                    "evidence": {"policies": plist},
                    "remediation_hint": "Prefer IAM Identity Center groups and permission sets; consolidate and remove redundant policies.",
                }
            )

    # Role trust: cross-account without ExternalId
    for role in data.get("roles", []):
        rname = role.get("RoleName", "unknown")
        trust = role.get("AssumeRolePolicyDocument") or {}
        for stmt in _policy_doc_statements(trust):
            if stmt.get("Effect") != "Allow":
                continue
            principal = stmt.get("Principal") or {}
            if not isinstance(principal, dict):
                continue
            aws_val = principal.get("AWS")
            if aws_val is None:
                continue
            principals = aws_val if isinstance(aws_val, list) else [aws_val]
            for p in principals:
                pstr = str(p)
                if ":root" in pstr or (len(pstr) == 12 and pstr.isdigit()):
                    cond = stmt.get("Condition") or {}
                    has_ext = False
                    if isinstance(cond, dict):
                        for inner in cond.values():
                            if isinstance(inner, dict) and "sts:ExternalId" in inner:
                                has_ext = True
                                break
                    if not has_ext:
                        findings.append(
                            {
                                "id": next_id("IAM"),
                                "title": "Cross-account role trust without ExternalId",
                                "severity": "High",
                                "resource": f"role/{rname}",
                                "category": "IAM",
                                "description": f"Role '{rname}' trusts another account principal without sts:ExternalId, increasing confused-deputy risk.",
                                "evidence": {"principal": pstr},
                                "remediation_hint": "Require ExternalId on cross-account trusts; scope to specific role ARNs not account root.",
                            }
                        )

    # Broad sts:AssumeRole on managed policies
    for pol in data.get("managed_policies", []):
        pname = pol.get("PolicyName", "unknown")
        parn = pol.get("PolicyArn", pname)
        doc = (pol.get("DefaultVersion") or {}).get("Document") or {}
        for stmt in _policy_doc_statements(doc):
            if stmt.get("Effect") != "Allow":
                continue
            acts = [a.lower() for a in _actions(stmt)]
            if "sts:assumerole" in acts and "*" in _resources(stmt):
                findings.append(
                    {
                        "id": next_id("IAM"),
                        "title": "Unscoped sts:AssumeRole permission",
                        "severity": "Critical",
                        "resource": parn,
                        "category": "IAM",
                        "description": f"Policy '{pname}' allows AssumeRole against Resource *.",
                        "evidence": {"policy_name": pname},
                        "remediation_hint": "List explicit role ARNs; deny AssumeRole via SCP except for approved paths.",
                    }
                )

    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit simulated IAM policies JSON.")
    parser.add_argument("input_path", help="Path to iam_policies.json")
    parser.add_argument("-o", "--output", help="Write findings JSON to this path (stdout if omitted)")
    args = parser.parse_args()

    with open(args.input_path, encoding="utf-8") as f:
        data = json.load(f)

    findings = audit(data)
    out = {
        "scan_type": "iam",
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
