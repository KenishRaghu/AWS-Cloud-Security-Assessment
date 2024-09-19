# Remediation playbook (simulated assessment)

This playbook mirrors how you would **partner with engineering and platform teams** after an assessment: plain-language risk, concrete AWS steps, and **guardrails** so issues do not return. It aligns with the finding categories produced by the local scanners over `environment/*.json`.

---

## IAM least privilege

### What is wrong

- **Wildcard `Action` / `Resource`:** A single policy can accidentally grant full admin or data access across the whole account.
- **Sensitive APIs without MFA conditions:** APIs that change identity (`iam:*`, broad `sts:AssumeRole`) should not be available to console users without MFA.
- **Policies on IAM users:** Long-lived access keys plus broad policies are a common breach path; roles and short-lived credentials are easier to bound.
- **Cross-account `AssumeRole` without `ExternalId`:** A third party (or attacker with a toehold elsewhere) can potentially assume your role unless you use a shared secret (`sts:ExternalId`) and tight trust.
- **Unscoped `sts:AssumeRole`:** Lets a principal try *any* role ARN in the account unless blocked elsewhere.

### Fix (examples)

**Replace wildcards with explicit ARNs** — edit the customer-managed policy JSON (console: IAM → Policies → Edit):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadSpecificBucket",
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::example-app-data",
        "arn:aws:s3:::example-app-data/*"
      ]
    }
  ]
}
```

**Require MFA for sensitive APIs** (illustrative condition on a human-facing policy):

```json
"Condition": {
  "BoolIfExists": { "aws:MultiFactorAuthPresent": "true" }
}
```

**Cross-account vendor role** — update trust policy (CLI):

```bash
aws iam update-assume-role-policy --role-name VendorRole --policy-document file://trust-with-external-id.json
```

Where `trust-with-external-id.json` includes `sts:ExternalId` under `Condition` and avoids `arn:aws:iam::VENDOR:root` where possible (prefer a **specific role ARN** in the vendor account).

**Detach admin from users** — Console: IAM → Users → user → Permissions → detach policy; attach a **permission set** via IAM Identity Center instead.

### How to prevent

- **Service Control Policies (SCPs):** Deny `iam:*`, `organizations:LeaveOrganization`, or `s3:PutBucketPolicy` with public principals at the OU level (tuned to your operating model).
- **AWS IAM Access Analyzer:** Continuously flag external access to resources; export findings to your ticketing system.
- **AWS Config rules:** e.g. `iam-policy-no-statements-with-admin-access`, `iam-user-unused-credentials-check` (enable after a pilot).
- **Guardrails:** Break-glass users in a separate OU with tighter monitoring; no static keys for humans where SSO is available.

---

## S3 bucket hardening

### What is wrong

- **Public ACLs / disabled Block Public Access:** Objects can become world-readable by mistake.
- **Missing default encryption:** Objects land unencrypted-at-rest relative to your baseline.
- **No versioning:** Accidental or malicious overwrites are irreversible without backups.
- **No access logging:** You lose object-level visibility for investigations.
- **Bucket policy `Principal: *` or account `root` with `s3:*`:** Too easy to over-share; hard to audit.

### Fix

**Block Public Access (all four) — CLI:**

```bash
aws s3api put-public-access-block --bucket YOUR_BUCKET \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

**Default encryption:**

```bash
aws s3api put-bucket-encryption --bucket YOUR_BUCKET \
  --server-side-encryption-configuration '{
    "Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms","KMSMasterKeyID":"alias/app-data"}}]}
  }'
```

**Versioning:**

```bash
aws s3api put-bucket-versioning --bucket YOUR_BUCKET \
  --versioning-configuration Status=Enabled
```

**Server access logging** to a dedicated log bucket with a restrictive bucket policy.

### How to prevent

- **Organization-wide Block Public Access** on S3 (account or OU setting).
- **AWS Config:** `s3-bucket-public-read-prohibited`, `s3-bucket-public-write-prohibited`, `s3-default-encryption-kms` (or SSE-S3 rule variants).
- **SCPs:** Deny changes that disable logging or encryption on buckets tagged `DataClassification=Confidential`.

---

## Security group tightening

### What is wrong

- **0.0.0.0/0 on 22, 3389, 3306, etc.:** Exposes management and database protocols to the entire internet.
- **Huge CIDRs (e.g. /8) to sensitive ports:** Any host in that range can reach the workload; lateral movement becomes trivial inside the “trusted” range.
- **Stale rules:** Descriptions like “unused” or “legacy” often mean nobody owns the risk anymore.

### Fix

**Replace open SSH with Session Manager** (no inbound 22 from internet):

1. Attach `AmazonSSMManagedInstanceCore` to the instance profile.
2. Remove `0.0.0.0/0` on port 22; allow SSH only from a bastion SG if still required.
3. Use **EC2 Instance Connect** or SSM for break-glass.

**Narrow database security groups** to the application tier SG:

```bash
aws ec2 authorize-security-group-ingress --group-id sg-db \
  --protocol tcp --port 3306 \
  --source-group sg-app
```

### How to prevent

- **AWS Config:** `vpc-sg-open-only-to-authorized-ports`, custom rule for “no 0.0.0.0/0 on 22/3389”.
- **Firewall Manager:** Central security group policies for the org.
- **Change management:** Terraform/CloudFormation reviews must flag `0.0.0.0/0` on sensitive ports.

---

## CloudTrail monitoring and log integrity

### What is wrong

- **Root usage:** Root should almost never appear in API logs; it bypasses normal IAM boundaries.
- **Console without MFA:** Stolen passwords become full console access.
- **`StopLogging` / `DeleteTrail`:** Classic defense-evasion; attackers hide subsequent actions.
- **`PutBucketPolicy` toward `Principal: *`:** Often precedes public data exposure.
- **Bursts of `AccessDenied`:** May indicate enumeration or automated tooling mapping permissions.

### Fix

**Least privilege for CloudTrail administration** — dedicate a security role; remove `cloudtrail:*` from general admins.

**Immutable log storage:** Trail to S3 with **Object Lock** (Governance or Compliance mode) and **MFA delete** where appropriate; replicate to a security account.

**Alerts (EventBridge examples to SNS/Lambda/SIEM):**

- `StopLogging`, `DeleteTrail`, `UpdateTrail`
- `ConsoleLogin` with `additionalEventData.MFAUsed = No` for privileged users
- `AssumeRole` with `errorCode` absent but source IP outside corporate ranges (tune carefully)

### How to prevent

- **Organization trail** with central bucket policy denying `s3:DeleteObject` except break-glass roles.
- **SCP:** Deny `cloudtrail:StopLogging` and `cloudtrail:DeleteTrail` except for a named security role (using `aws:PrincipalArn` condition).
- **GuardDuty + CloudTrail Lake:** Correlate IAM and S3 findings with API history.

---

## How this supports interview narrative

- You can describe **working with owners** (“we paired with the data team to scope the S3 prefix ARNs”) and **translating risk** (“public read on this bucket classifies as customer PII exposure, not just a misconfiguration”).
- The **playbook** is the artifact reviewers often care about more than raw tool output: it shows you know **AWS-native controls**, not only Python.
