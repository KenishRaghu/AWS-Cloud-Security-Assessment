# AWS Cloud Security Assessment (simulated)

Portfolio project that demonstrates **how you assess AWS posture**—identity, data exposure, network reachability, and audit log behavior—**without** connecting to a real account, Terraform, LocalStack, or third-party scanners like Prowler or ScoutSuite.

## What this is

- **`environment/`** — JSON snapshots that **simulate** IAM policies, S3 bucket settings, EC2 security groups, and CloudTrail-style events. The data is **intentionally flawed** so you can show detection and storytelling.
- **`scripts/`** — Small Python tools (stdlib only) that **parse those JSON files** and emit structured findings. **These scripts are the audit automation**; the security judgment lives in the rules, the report narrative, and `docs/remediation_playbook.md`.
- **`reports/`** — Generated Markdown: executive-style assessment plus a **CloudTrail incident timeline** you can walk through verbally.

This is **not** infrastructure-as-code and **not** a live pentest. It is a **repeatable assessment methodology** you can demo locally in interviews.

## Methodology (how to talk about it)

1. **Design / configuration review** — Understand accounts, trust boundaries, and data classes from exports (here: JSON under `environment/`).
2. **Automated audit** — Run deterministic checks for anti-patterns (wildcards, public S3, open SG ports, dangerous trust policies).
3. **Log analysis** — Interpret CloudTrail-like events for **root use**, **MFA gaps**, **unusual IPs**, **log tampering**, and **enumeration bursts**.
4. **Risk assessment** — Severity, likelihood/impact framing, and prioritization (see generated `reports/assessment_report.md`).
5. **Remediation** — Partner with teams using actionable console/CLI/policy steps and **preventive guardrails** (SCPs, Config, monitoring) in `docs/remediation_playbook.md`.

## Repository layout

```
├── environment/
│   ├── iam_policies.json
│   ├── s3_bucket_configs.json
│   ├── security_groups.json
│   └── cloudtrail_logs.json
├── scripts/
│   ├── iam_auditor.py
│   ├── s3_auditor.py
│   ├── sg_auditor.py
│   ├── cloudtrail_analyzer.py
│   └── report_generator.py
├── reports/                    # JSON inputs + generated Markdown (after you run the pipeline)
├── docs/
│   └── remediation_playbook.md
├── requirements.txt
└── README.md
```

## Prerequisites

- **Python 3.9+** recommended (uses `datetime.fromisoformat` in the CloudTrail analyzer).

No AWS credentials, **no boto3**, no pip packages required.

## How to run the full assessment

From the repository root:

```bash
mkdir -p reports

python3 scripts/iam_auditor.py environment/iam_policies.json -o reports/iam_findings.json
python3 scripts/s3_auditor.py environment/s3_bucket_configs.json -o reports/s3_findings.json
python3 scripts/sg_auditor.py environment/security_groups.json -o reports/sg_findings.json
python3 scripts/cloudtrail_analyzer.py environment/cloudtrail_logs.json -o reports/cloudtrail_analysis.json

python3 scripts/report_generator.py --out-dir reports
```

Outputs:

- `reports/iam_findings.json`, `reports/s3_findings.json`, `reports/sg_findings.json`, `reports/cloudtrail_analysis.json` — machine-readable findings (and CloudTrail timeline entries).
- `reports/assessment_report.md` — executive summary, findings table, detail sections, risk matrix, remediation roadmap.
- `reports/cloudtrail_incident_timeline.md` — chronological story: enumeration → suspicious role use → log tampering → public bucket policy change → blocked escalation attempts.

To print findings to the terminal instead of a file, omit `-o`:

```bash
python3 scripts/iam_auditor.py environment/iam_policies.json
```

## What each script does

| Script | Input | Focus |
|--------|--------|--------|
| `iam_auditor.py` | `iam_policies.json` | Wildcard `Action`/`Resource`, sensitive APIs without MFA conditions, risky user attachments, cross-account trust without `ExternalId`, unscoped `sts:AssumeRole`, simulated credential material in policy text |
| `s3_auditor.py` | `s3_bucket_configs.json` | Public access / Block Public Access gaps, missing encryption, versioning off, access logging off, dangerous bucket policies |
| `sg_auditor.py` | `security_groups.json` | Internet-reachable sensitive ports, overly large CIDRs, permissive egress, stale “unused” rules |
| `cloudtrail_analyzer.py` | `cloudtrail_logs.json` | Root activity, console without MFA, `AssumeRole` from non-corporate IPs, `StopLogging` / `DeleteTrail`, risky `PutBucketPolicy`, `AccessDenied` bursts |
| `report_generator.py` | JSON outputs above | Unified `assessment_report.md` + narrative `cloudtrail_incident_timeline.md` |

## Sample findings (illustrative)

After running the pipeline you should see issues such as:

- **Critical:** Administrator-equivalent policy attached to a **service user**; S3 bucket **public** via ACL and policy; security group **SSH from 0.0.0.0/0**; **CloudTrail `StopLogging`**; **bucket policy** changes toward **public principals**.
- **High:** Cross-account role trust **without ExternalId**; finance bucket **no default encryption**; **RDP open to the world**; **console logins without MFA** in the log sample.
- **Medium:** **Unrestricted egress**; **no S3 access logging** on sensitive buckets; bursts of **`AccessDenied`** suggesting enumeration.

Exact counts depend on the current JSON; the **report** aggregates everything with severities.

## AWS architecture angles (why this reads as security, not “Python homework”)

- **Identity:** Separates **human**, **machine**, and **cross-account** trust, and shows why **roles + external ID + MFA conditions** matter.
- **Data plane:** S3 **defense in depth** — ACL, Block Public Access, bucket policy, encryption, versioning, logging.
- **Network:** Security groups as **stateful instance firewalls**; why **0.0.0.0/0** on management and database ports fails every reasonable risk model.
- **Detective:** CloudTrail as the **audit backbone**, and why **`StopLogging`** is treated as an incident-class signal.

## License

Use freely for portfolio and interview preparation. Synthetic data only—do not map account IDs or IPs to real organizations.
