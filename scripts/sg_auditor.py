#!/usr/bin/env python3
"""Simulated security group audit from static JSON (EC2-style rules)."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

SENSITIVE_PORTS = {22, 3389, 3306, 5432, 6379, 27017}


def _cidr_too_broad(cidr: str) -> bool:
    if "/" not in cidr:
        return False
    addr, _, plen_s = cidr.partition("/")
    try:
        plen = int(plen_s)
    except ValueError:
        return False
    if ":" in addr:
        return plen < 48
    return plen < 16


def _covers_world_v4(cidr: str) -> bool:
    return cidr in ("0.0.0.0/0", "::/0")


def audit(data: dict) -> list[dict]:
    findings: list[dict] = []
    n = 0

    def nid() -> str:
        nonlocal n
        n += 1
        return f"SG-{n:03d}"

    for sg in data.get("security_groups", []):
        gid = sg.get("GroupId", "unknown")
        gname = sg.get("GroupName", "unknown")
        resource = f"{gname} ({gid})"

        for perm in sg.get("IpPermissions") or []:
            proto = perm.get("IpProtocol", "")
            from_p = perm.get("FromPort")
            to_p = perm.get("ToPort")
            for r in perm.get("IpRanges") or []:
                cidr = r.get("CidrIp", "")
                desc = r.get("Description", "")
                if proto == "tcp" and from_p is not None and to_p is not None:
                    port_range = set(range(int(from_p), int(to_p) + 1))
                    hit_ports = sorted(port_range & SENSITIVE_PORTS)
                    if hit_ports and _covers_world_v4(cidr):
                        findings.append(
                            {
                                "id": nid(),
                                "title": "Sensitive port open to the internet",
                                "severity": "Critical",
                                "resource": resource,
                                "category": "EC2",
                                "description": f"Inbound TCP {hit_ports} allowed from {cidr} (security group '{gname}').",
                                "evidence": {
                                    "group_id": gid,
                                    "ports": hit_ports,
                                    "cidr": cidr,
                                    "rule_description": desc,
                                },
                                "remediation_hint": "Restrict to bastion IPs or SSM Session Manager; use /32 corp egress IPs only.",
                            }
                        )
                    elif hit_ports and _cidr_too_broad(cidr):
                        findings.append(
                            {
                                "id": nid(),
                                "title": "Sensitive port exposed to an overly broad CIDR",
                                "severity": "High",
                                "resource": resource,
                                "category": "EC2",
                                "description": f"Ports {hit_ports} reachable from large network {cidr}.",
                                "evidence": {"group_id": gid, "cidr": cidr},
                                "remediation_hint": "Narrow to application subnet CIDRs or security group references.",
                            }
                        )
                if proto == "-1" and _covers_world_v4(cidr):
                    findings.append(
                        {
                            "id": nid(),
                            "title": "All protocols open from internet",
                            "severity": "Critical",
                            "resource": resource,
                            "category": "EC2",
                            "description": "Rule allows all traffic (-1) from 0.0.0.0/0 inbound.",
                            "evidence": {"group_id": gid, "cidr": cidr},
                            "remediation_hint": "Remove; allow only required protocols and ports.",
                        }
                    )

        egress_all = False
        for perm in sg.get("IpPermissionsEgress") or []:
            if perm.get("IpProtocol") == "-1":
                for r in perm.get("IpRanges") or []:
                    if _covers_world_v4(r.get("CidrIp", "")):
                        egress_all = True
        if egress_all:
            findings.append(
                {
                    "id": nid(),
                    "title": "Unrestricted egress (all traffic to 0.0.0.0/0)",
                    "severity": "Medium",
                    "resource": resource,
                    "category": "EC2",
                    "description": "Security group allows all outbound traffic. Often acceptable, but risky for regulated data planes.",
                    "evidence": {"group_id": gid},
                    "remediation_hint": "For sensitive tiers, restrict egress to required endpoints (VPC endpoints, known IPs).",
                }
            )

        # Unused rule heuristic: description mentions unused
        for perm in sg.get("IpPermissions") or []:
            for r in perm.get("IpRanges") or []:
                d = (r.get("Description") or "").lower()
                if "unused" in d or "legacy" in d:
                    findings.append(
                        {
                            "id": nid(),
                            "title": "Stale or unused security group rule (description hint)",
                            "severity": "Low",
                            "resource": resource,
                            "category": "EC2",
                            "description": "Rule description suggests the entry is no longer needed.",
                            "evidence": {
                                "cidr": r.get("CidrIp"),
                                "description": r.get("Description"),
                                "ports": f"{perm.get('FromPort')}-{perm.get('ToPort')}",
                            },
                            "remediation_hint": "Review with owners; remove rules quarterly as part of SG hygiene.",
                        }
                    )

    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit simulated security_groups.json")
    parser.add_argument("input_path", help="Path to security_groups.json")
    parser.add_argument("-o", "--output", help="Write findings JSON to this path")
    args = parser.parse_args()

    with open(args.input_path, encoding="utf-8") as f:
        data = json.load(f)

    findings = audit(data)
    out = {
        "scan_type": "security_group",
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
