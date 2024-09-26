# AWS Cloud Security Assessment Report

**Assessment artifact generated:** `2026-04-10T22:09:54Z`  
**Scope:** Simulated static configuration and log export (`environment/*.json`) — no live AWS account required.

## Executive summary

This report summarizes control gaps identified through a **design review** of IAM and data-plane configuration, **automated policy checks** over JSON exports, and **CloudTrail-style log analysis** for detective signals. The simulated account shows a **material concentration of critical issues** in identity trust, network exposure, and S3 public-access posture, compounded by **log tampering and suspicious role assumption patterns** in the sample timeline.

- **Critical findings:** 17
- **High findings:** 21
- **Total findings:** 55

Overall, the organization would be exposed to **credential theft leading to data exfiltration**, **lateral movement via over-permissive security groups**, and **impaired forensics** if logging is interrupted. Remediation should prioritize **stopping public and root-level risk**, then **tightening cross-account trust**, then **sustained detective controls** (immutable audit trail, alerting).

## Findings

| ID | Domain | Severity | Title | Affected resource |
|----|--------|----------|-------|-------------------|
| CT-003 | CloudTrail | Critical | CloudTrail tampering indicator: StopLogging (succeeded) | org-main-trail |
| CT-004 | CloudTrail | Critical | Root account API usage detected | account root |
| CT-006 | CloudTrail | Critical | Root account API usage detected | account root |
| CT-007 | CloudTrail | Critical | Root account API usage detected | account root |
| CT-008 | CloudTrail | Critical | PutBucketPolicy altering public or wildcard principal | corp-public-assets-prod |
| IAM-001 | IAM | Critical | Overly permissive IAM policy statement | arn:aws:iam::111122223333:policy/AdministratorAccess-Simulated |
| IAM-004 | IAM | Critical | Overly permissive IAM policy statement | arn:aws:iam::111122223333:policy/PowerUserWithStar |
| IAM-009 | IAM | Critical | Overly permissive IAM policy statement | arn:aws:iam::111122223333:policy/HumanAdminNoMFACondition |
| IAM-011 | IAM | Critical | Simulated inline credential material in policy export | arn:aws:iam::111122223333:policy/CIEmbeddedKeySimulation |
| IAM-012 | IAM | Critical | Simulated inline credential material in policy export | arn:aws:iam::111122223333:policy/CIEmbeddedKeySimulation |
| IAM-013 | IAM | Critical | Overly permissive IAM policy statement | arn:aws:iam::111122223333:policy/BroadAssumeRoleTrust |
| IAM-019 | IAM | Critical | Unscoped sts:AssumeRole permission | arn:aws:iam::111122223333:policy/HumanAdminNoMFACondition |
| IAM-020 | IAM | Critical | Unscoped sts:AssumeRole permission | arn:aws:iam::111122223333:policy/BroadAssumeRoleTrust |
| S3-001 | S3 | Critical | S3 bucket exposes or allows public access configuration | s3://corp-public-assets-prod |
| S3-005 | S3 | Critical | Bucket policy allows anonymous or public object access | s3://corp-public-assets-prod |
| SG-001 | SG | Critical | Sensitive port open to the internet | web-tier-public (sg-0a1b2c3d4e5f67890) |
| SG-005 | SG | Critical | Sensitive port open to the internet | bastion-legacy (sg-01112233445566778) |
| CT-001 | CloudTrail | High | Console login without MFA | IAMUser:contractor-analyst |
| CT-002 | CloudTrail | High | AssumeRole from non-corporate source IP | IAMUser:contractor-analyst |
| CT-005 | CloudTrail | High | Console login without MFA | Root |
| CT-009 | CloudTrail | High | CloudTrail tampering indicator: DeleteTrail (returned AccessDenied) | legacy-audit-trail |
| CT-010 | CloudTrail | High | AssumeRole from non-corporate source IP | IAMUser:svc-legacy-deploy |
| CT-011 | CloudTrail | High | Console login without MFA | IAMUser:breakglass-emergency |
| IAM-002 | IAM | High | Sensitive IAM/API actions without MFA condition | arn:aws:iam::111122223333:policy/AdministratorAccess-Simulated |
| IAM-003 | IAM | High | High-risk managed policy attached directly to IAM users | arn:aws:iam::111122223333:policy/AdministratorAccess-Simulated |
| IAM-005 | IAM | High | Sensitive IAM/API actions without MFA condition | arn:aws:iam::111122223333:policy/PowerUserWithStar |
| IAM-006 | IAM | High | High-risk managed policy attached directly to IAM users | arn:aws:iam::111122223333:policy/PowerUserWithStar |
| IAM-010 | IAM | High | Sensitive IAM/API actions without MFA condition | arn:aws:iam::111122223333:policy/HumanAdminNoMFACondition |
| IAM-014 | IAM | High | Sensitive IAM/API actions without MFA condition | arn:aws:iam::111122223333:policy/BroadAssumeRoleTrust |
| IAM-015 | IAM | High | High-risk managed policy attached directly to IAM users | arn:aws:iam::111122223333:policy/BroadAssumeRoleTrust |
| IAM-016 | IAM | High | Inline user policy with wildcard Action or Resource | user/contractor-analyst/InlineS3ReadAll |
| IAM-018 | IAM | High | Cross-account role trust without ExternalId | role/CrossAccountVendorRole |
| S3-002 | S3 | High | Default encryption not configured for bucket | s3://corp-public-assets-prod |
| S3-006 | S3 | High | Default encryption not configured for bucket | s3://finance-reports-internal |
| S3-008 | S3 | High | Overly broad bucket policy (account root with s3:*) | s3://finance-reports-internal |
| S3-010 | S3 | High | Default encryption not configured for bucket | s3://vendor-handoff-bucket |
| S3-012 | S3 | High | Default encryption not configured for bucket | s3://deprecated-warehouse |
| SG-003 | SG | High | Sensitive port exposed to an overly broad CIDR | db-tier-mysql (sg-0f9e8d7c6b5a43210) |
| CT-012 | CloudTrail | Medium | Burst of AccessDenied errors (possible enumeration) | IAMUser:contractor-analyst |
| CT-013 | CloudTrail | Medium | Burst of AccessDenied errors (possible enumeration) | arn:aws:sts::111122223333:assumed-role/CrossAccountVendorRole/automation |
| IAM-017 | IAM | Medium | Multiple managed policies attached to a single IAM user | user/svc-legacy-deploy |
| S3-003 | S3 | Medium | S3 versioning not enabled | s3://corp-public-assets-prod |
| S3-004 | S3 | Medium | Server access logging not enabled | s3://corp-public-assets-prod |
| S3-007 | S3 | Medium | Server access logging not enabled | s3://finance-reports-internal |
| S3-009 | S3 | Medium | S3 versioning not enabled | s3://app-user-uploads-staging |
| S3-011 | S3 | Medium | Server access logging not enabled | s3://vendor-handoff-bucket |
| S3-013 | S3 | Medium | S3 versioning not enabled | s3://deprecated-warehouse |
| S3-014 | S3 | Medium | Server access logging not enabled | s3://deprecated-warehouse |
| SG-002 | SG | Medium | Unrestricted egress (all traffic to 0.0.0.0/0) | web-tier-public (sg-0a1b2c3d4e5f67890) |
| SG-004 | SG | Medium | Unrestricted egress (all traffic to 0.0.0.0/0) | db-tier-mysql (sg-0f9e8d7c6b5a43210) |
| SG-006 | SG | Medium | Unrestricted egress (all traffic to 0.0.0.0/0) | bastion-legacy (sg-01112233445566778) |
| SG-008 | SG | Medium | Unrestricted egress (all traffic to 0.0.0.0/0) | lambda-eni-placeholder (sg-0deadbeefcafe0001) |
| IAM-007 | IAM | Low | Potentially unused or stale IAM permissions | arn:aws:iam::111122223333:policy/AppRuntimePolicy |
| IAM-008 | IAM | Low | Potentially unused or stale IAM permissions | arn:aws:iam::111122223333:policy/AppRuntimePolicy |
| SG-007 | SG | Low | Stale or unused security group rule (description hint) | internal-app-only (sg-09998877665544332) |

### Detailed findings

#### CT-003 — CloudTrail tampering indicator: StopLogging (succeeded)

- **Severity:** Critical
- **Domain:** CloudTrail
- **Resource:** `org-main-trail`

**Description:** Logging pipeline modification (or attempted modification) is a common defense-evasion technique; successful StopLogging is especially severe.

**Evidence (excerpt):** `{"eventTime": "2026-03-10T22:00:00Z", "principal": "arn:aws:sts::111122223333:assumed-role/CrossAccountVendorRole/vendor-sync", "sourceIPAddress": "185.220.101.33", "errorCode": null}`

**Remediation (summary):** Restrict cloudtrail:* to security admin role; immutable S3 + SNS alerts on StopLogging.

---

#### CT-004 — Root account API usage detected

- **Severity:** Critical
- **Domain:** CloudTrail
- **Resource:** `account root`

**Description:** Root should be locked away; any interactive or API use is high risk.

**Evidence (excerpt):** `{"eventName": "ConsoleLogin", "eventTime": "2026-03-11T07:30:00Z", "sourceIPAddress": "198.51.100.100"}`

**Remediation (summary):** Remove root access keys; enable MFA on root; use break-glass procedures only.

---

#### CT-006 — Root account API usage detected

- **Severity:** Critical
- **Domain:** CloudTrail
- **Resource:** `account root`

**Description:** Root should be locked away; any interactive or API use is high risk.

**Evidence (excerpt):** `{"eventName": "GetAccountSummary", "eventTime": "2026-03-11T08:00:00Z", "sourceIPAddress": "198.51.100.100"}`

**Remediation (summary):** Remove root access keys; enable MFA on root; use break-glass procedures only.

---

#### CT-007 — Root account API usage detected

- **Severity:** Critical
- **Domain:** CloudTrail
- **Resource:** `account root`

**Description:** Root should be locked away; any interactive or API use is high risk.

**Evidence (excerpt):** `{"eventName": "ListAccountAliases", "eventTime": "2026-03-11T08:05:00Z", "sourceIPAddress": "198.51.100.100"}`

**Remediation (summary):** Remove root access keys; enable MFA on root; use break-glass procedures only.

---

#### CT-008 — PutBucketPolicy altering public or wildcard principal

- **Severity:** Critical
- **Domain:** CloudTrail
- **Resource:** `corp-public-assets-prod`

**Description:** Bucket policy update referencing wildcard principal — often public-read misconfiguration.

**Evidence (excerpt):** `{"eventTime": "2026-03-11T09:10:00Z", "principal": "arn:aws:sts::111122223333:assumed-role/CrossAccountVendorRole/vendor-sync"}`

**Remediation (summary):** Revert policy; enable Block Public Access; investigate principal that issued change.

---

#### IAM-001 — Overly permissive IAM policy statement

- **Severity:** Critical
- **Domain:** IAM
- **Resource:** `arn:aws:iam::111122223333:policy/AdministratorAccess-Simulated`

**Description:** Managed policy 'AdministratorAccess-Simulated' contains a broad Allow: Statement allows Action *.

**Evidence (excerpt):** `{"policy_name": "AdministratorAccess-Simulated", "statement_sid": null}`

**Remediation (summary):** Replace * with explicit actions/resources; split duties across roles.

---

#### IAM-004 — Overly permissive IAM policy statement

- **Severity:** Critical
- **Domain:** IAM
- **Resource:** `arn:aws:iam::111122223333:policy/PowerUserWithStar`

**Description:** Managed policy 'PowerUserWithStar' contains a broad Allow: Statement allows Action *.

**Evidence (excerpt):** `{"policy_name": "PowerUserWithStar", "statement_sid": "WildcardManagement"}`

**Remediation (summary):** Replace * with explicit actions/resources; split duties across roles.

---

#### IAM-009 — Overly permissive IAM policy statement

- **Severity:** Critical
- **Domain:** IAM
- **Resource:** `arn:aws:iam::111122223333:policy/HumanAdminNoMFACondition`

**Description:** Managed policy 'HumanAdminNoMFACondition' contains a broad Allow: Statement allows Resource *.

**Evidence (excerpt):** `{"policy_name": "HumanAdminNoMFACondition", "statement_sid": "AdminWithoutMFAReq"}`

**Remediation (summary):** Replace * with explicit actions/resources; split duties across roles.

---

#### IAM-011 — Simulated inline credential material in policy export

- **Severity:** Critical
- **Domain:** IAM
- **Resource:** `arn:aws:iam::111122223333:policy/CIEmbeddedKeySimulation`

**Description:** Possible AWS access key id pattern in policy text

**Evidence (excerpt):** `{"policy_name": "CIEmbeddedKeySimulation"}`

**Remediation (summary):** Rotate any exposed keys; store secrets in Secrets Manager; use IAM Roles for workloads.

---

#### IAM-012 — Simulated inline credential material in policy export

- **Severity:** Critical
- **Domain:** IAM
- **Resource:** `arn:aws:iam::111122223333:policy/CIEmbeddedKeySimulation`

**Description:** Possible secret key reference in policy text

**Evidence (excerpt):** `{"policy_name": "CIEmbeddedKeySimulation"}`

**Remediation (summary):** Rotate any exposed keys; store secrets in Secrets Manager; use IAM Roles for workloads.

---

#### IAM-013 — Overly permissive IAM policy statement

- **Severity:** Critical
- **Domain:** IAM
- **Resource:** `arn:aws:iam::111122223333:policy/BroadAssumeRoleTrust`

**Description:** Managed policy 'BroadAssumeRoleTrust' contains a broad Allow: Statement allows Resource *.

**Evidence (excerpt):** `{"policy_name": "BroadAssumeRoleTrust", "statement_sid": null}`

**Remediation (summary):** Replace * with explicit actions/resources; split duties across roles.

---

#### IAM-019 — Unscoped sts:AssumeRole permission

- **Severity:** Critical
- **Domain:** IAM
- **Resource:** `arn:aws:iam::111122223333:policy/HumanAdminNoMFACondition`

**Description:** Policy 'HumanAdminNoMFACondition' allows AssumeRole against Resource *.

**Evidence (excerpt):** `{"policy_name": "HumanAdminNoMFACondition"}`

**Remediation (summary):** List explicit role ARNs; deny AssumeRole via SCP except for approved paths.

---

#### IAM-020 — Unscoped sts:AssumeRole permission

- **Severity:** Critical
- **Domain:** IAM
- **Resource:** `arn:aws:iam::111122223333:policy/BroadAssumeRoleTrust`

**Description:** Policy 'BroadAssumeRoleTrust' allows AssumeRole against Resource *.

**Evidence (excerpt):** `{"policy_name": "BroadAssumeRoleTrust"}`

**Remediation (summary):** List explicit role ARNs; deny AssumeRole via SCP except for approved paths.

---

#### S3-001 — S3 bucket exposes or allows public access configuration

- **Severity:** Critical
- **Domain:** S3
- **Resource:** `s3://corp-public-assets-prod`

**Description:** Public ACLs and/or S3 Block Public Access not fully enabled increases risk of data exposure.

**Evidence (excerpt):** `{"ACL": "public-read", "PublicAccessBlockConfiguration": {"BlockPublicAcls": false, "IgnorePublicAcls": false, "BlockPublicPolicy": false, "RestrictPublicBuckets": false}}`

**Remediation (summary):** Enable all four Block Public Access settings; remove public ACLs; use CloudFront OAC for public content.

---

#### S3-005 — Bucket policy allows anonymous or public object access

- **Severity:** Critical
- **Domain:** S3
- **Resource:** `s3://corp-public-assets-prod`

**Description:** A bucket policy statement grants GetObject (or s3:*) to a public principal.

**Evidence (excerpt):** `{"BucketPolicy": {"Version": "2012-10-17", "Statement": [{"Sid": "PublicReadGetObject", "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::corp-public-assets-prod/*"}]}}`

**Remediation (summary):** Remove Principal *; use OAI/OAC, signed URLs, or authenticated viewers only.

---

#### SG-001 — Sensitive port open to the internet

- **Severity:** Critical
- **Domain:** SG
- **Resource:** `web-tier-public (sg-0a1b2c3d4e5f67890)`

**Description:** Inbound TCP [22] allowed from 0.0.0.0/0 (security group 'web-tier-public').

**Evidence (excerpt):** `{"group_id": "sg-0a1b2c3d4e5f67890", "ports": [22], "cidr": "0.0.0.0/0", "rule_description": "temporary ssh"}`

**Remediation (summary):** Restrict to bastion IPs or SSM Session Manager; use /32 corp egress IPs only.

---

#### SG-005 — Sensitive port open to the internet

- **Severity:** Critical
- **Domain:** SG
- **Resource:** `bastion-legacy (sg-01112233445566778)`

**Description:** Inbound TCP [3389] allowed from 0.0.0.0/0 (security group 'bastion-legacy').

**Evidence (excerpt):** `{"group_id": "sg-01112233445566778", "ports": [3389], "cidr": "0.0.0.0/0", "rule_description": ""}`

**Remediation (summary):** Restrict to bastion IPs or SSM Session Manager; use /32 corp egress IPs only.

---

#### CT-001 — Console login without MFA

- **Severity:** High
- **Domain:** CloudTrail
- **Resource:** `IAMUser:contractor-analyst`

**Description:** Successful console authentication reported MFAUsed=No.

**Evidence (excerpt):** `{"eventTime": "2026-03-10T17:45:11Z", "sourceIPAddress": "203.0.113.88"}`

**Remediation (summary):** Enforce MFA via IAM policy or Identity Center; deny console without MFA.

---

#### CT-002 — AssumeRole from non-corporate source IP

- **Severity:** High
- **Domain:** CloudTrail
- **Resource:** `IAMUser:contractor-analyst`

**Description:** Role assumption from IP 185.220.101.33 outside simulated trusted corporate ranges.

**Evidence (excerpt):** `{"eventTime": "2026-03-10T19:00:00Z", "requestParameters": {"roleArn": "arn:aws:iam::111122223333:role/CrossAccountVendorRole", "roleSessionName": "vendor-sync"}}`

**Remediation (summary):** Tighten role trust with SourceIp / vpc conditions; alert on geo anomalies.

---

#### CT-005 — Console login without MFA

- **Severity:** High
- **Domain:** CloudTrail
- **Resource:** `Root`

**Description:** Successful console authentication reported MFAUsed=No.

**Evidence (excerpt):** `{"eventTime": "2026-03-11T07:30:00Z", "sourceIPAddress": "198.51.100.100"}`

**Remediation (summary):** Enforce MFA via IAM policy or Identity Center; deny console without MFA.

---

#### CT-009 — CloudTrail tampering indicator: DeleteTrail (returned AccessDenied)

- **Severity:** High
- **Domain:** CloudTrail
- **Resource:** `legacy-audit-trail`

**Description:** Logging pipeline modification (or attempted modification) is a common defense-evasion technique; successful StopLogging is especially severe.

**Evidence (excerpt):** `{"eventTime": "2026-03-11T09:45:00Z", "principal": "arn:aws:sts::111122223333:assumed-role/CrossAccountVendorRole/vendor-sync", "sourceIPAddress": "185.220.101.33", "errorCode": "AccessDenied"}`

**Remediation (summary):** Restrict cloudtrail:* to security admin role; immutable S3 + SNS alerts on StopLogging.

---

#### CT-010 — AssumeRole from non-corporate source IP

- **Severity:** High
- **Domain:** CloudTrail
- **Resource:** `IAMUser:svc-legacy-deploy`

**Description:** Role assumption from IP 45.33.32.156 outside simulated trusted corporate ranges.

**Evidence (excerpt):** `{"eventTime": "2026-03-12T07:00:00Z", "requestParameters": {"roleArn": "arn:aws:iam::111122223333:role/CrossAccountVendorRole", "roleSessionName": "automation"}}`

**Remediation (summary):** Tighten role trust with SourceIp / vpc conditions; alert on geo anomalies.

---

#### CT-011 — Console login without MFA

- **Severity:** High
- **Domain:** CloudTrail
- **Resource:** `IAMUser:breakglass-emergency`

**Description:** Successful console authentication reported MFAUsed=No.

**Evidence (excerpt):** `{"eventTime": "2026-03-13T10:00:00Z", "sourceIPAddress": "192.0.2.200"}`

**Remediation (summary):** Enforce MFA via IAM policy or Identity Center; deny console without MFA.

---

#### IAM-002 — Sensitive IAM/API actions without MFA condition

- **Severity:** High
- **Domain:** IAM
- **Resource:** `arn:aws:iam::111122223333:policy/AdministratorAccess-Simulated`

**Description:** Policy 'AdministratorAccess-Simulated' grants sensitive capabilities without aws:MultiFactorAuthPresent (or similar).

**Evidence (excerpt):** `{"policy_name": "AdministratorAccess-Simulated", "actions_sample": ["*"]}`

**Remediation (summary):** Add MFA conditions for human principals; use roles for automation with externalId.

---

#### IAM-003 — High-risk managed policy attached directly to IAM users

- **Severity:** High
- **Domain:** IAM
- **Resource:** `arn:aws:iam::111122223333:policy/AdministratorAccess-Simulated`

**Description:** Policy 'AdministratorAccess-Simulated' with broad permissions is attached to users ['svc-legacy-deploy'] instead of roles.

**Evidence (excerpt):** `{"users": ["svc-legacy-deploy"]}`

**Remediation (summary):** Move humans to SSO/roles; attach broad policies only to instance/task roles with trust constraints.

---

#### IAM-005 — Sensitive IAM/API actions without MFA condition

- **Severity:** High
- **Domain:** IAM
- **Resource:** `arn:aws:iam::111122223333:policy/PowerUserWithStar`

**Description:** Policy 'PowerUserWithStar' grants sensitive capabilities without aws:MultiFactorAuthPresent (or similar).

**Evidence (excerpt):** `{"policy_name": "PowerUserWithStar", "actions_sample": ["*"]}`

**Remediation (summary):** Add MFA conditions for human principals; use roles for automation with externalId.

---

#### IAM-006 — High-risk managed policy attached directly to IAM users

- **Severity:** High
- **Domain:** IAM
- **Resource:** `arn:aws:iam::111122223333:policy/PowerUserWithStar`

**Description:** Policy 'PowerUserWithStar' with broad permissions is attached to users ['breakglass-emergency'] instead of roles.

**Evidence (excerpt):** `{"users": ["breakglass-emergency"]}`

**Remediation (summary):** Move humans to SSO/roles; attach broad policies only to instance/task roles with trust constraints.

---

#### IAM-010 — Sensitive IAM/API actions without MFA condition

- **Severity:** High
- **Domain:** IAM
- **Resource:** `arn:aws:iam::111122223333:policy/HumanAdminNoMFACondition`

**Description:** Policy 'HumanAdminNoMFACondition' grants sensitive capabilities without aws:MultiFactorAuthPresent (or similar).

**Evidence (excerpt):** `{"policy_name": "HumanAdminNoMFACondition", "actions_sample": ["iam:CreateUser", "iam:AttachUserPolicy", "iam:PutUserPolicy", "sts:AssumeRole"]}`

**Remediation (summary):** Add MFA conditions for human principals; use roles for automation with externalId.

---

#### IAM-014 — Sensitive IAM/API actions without MFA condition

- **Severity:** High
- **Domain:** IAM
- **Resource:** `arn:aws:iam::111122223333:policy/BroadAssumeRoleTrust`

**Description:** Policy 'BroadAssumeRoleTrust' grants sensitive capabilities without aws:MultiFactorAuthPresent (or similar).

**Evidence (excerpt):** `{"policy_name": "BroadAssumeRoleTrust", "actions_sample": ["sts:AssumeRole"]}`

**Remediation (summary):** Add MFA conditions for human principals; use roles for automation with externalId.

---

#### IAM-015 — High-risk managed policy attached directly to IAM users

- **Severity:** High
- **Domain:** IAM
- **Resource:** `arn:aws:iam::111122223333:policy/BroadAssumeRoleTrust`

**Description:** Policy 'BroadAssumeRoleTrust' with broad permissions is attached to users ['contractor-analyst'] instead of roles.

**Evidence (excerpt):** `{"users": ["contractor-analyst"]}`

**Remediation (summary):** Move humans to SSO/roles; attach broad policies only to instance/task roles with trust constraints.

---

#### IAM-016 — Inline user policy with wildcard Action or Resource

- **Severity:** High
- **Domain:** IAM
- **Resource:** `user/contractor-analyst/InlineS3ReadAll`

**Description:** User 'contractor-analyst' inline policy 'InlineS3ReadAll': Statement allows Resource *.

**Evidence (excerpt):** `{"user": "contractor-analyst", "inline_policy": "InlineS3ReadAll"}`

**Remediation (summary):** Convert to managed policy with review; scope resources to bucket/table ARNs.

---

#### IAM-018 — Cross-account role trust without ExternalId

- **Severity:** High
- **Domain:** IAM
- **Resource:** `role/CrossAccountVendorRole`

**Description:** Role 'CrossAccountVendorRole' trusts another account principal without sts:ExternalId, increasing confused-deputy risk.

**Evidence (excerpt):** `{"principal": "arn:aws:iam::999988887777:root"}`

**Remediation (summary):** Require ExternalId on cross-account trusts; scope to specific role ARNs not account root.

---

#### S3-002 — Default encryption not configured for bucket

- **Severity:** High
- **Domain:** S3
- **Resource:** `s3://corp-public-assets-prod`

**Description:** Objects may be stored without default SSE-S3 or SSE-KMS at rest.

**Evidence (excerpt):** `{"ServerSideEncryptionConfiguration": null}`

**Remediation (summary):** Enable default bucket encryption; prefer KMS CMK for sensitive data with key policies.

---

#### S3-006 — Default encryption not configured for bucket

- **Severity:** High
- **Domain:** S3
- **Resource:** `s3://finance-reports-internal`

**Description:** Objects may be stored without default SSE-S3 or SSE-KMS at rest.

**Evidence (excerpt):** `{"ServerSideEncryptionConfiguration": null}`

**Remediation (summary):** Enable default bucket encryption; prefer KMS CMK for sensitive data with key policies.

---

#### S3-008 — Overly broad bucket policy (account root with s3:*)

- **Severity:** High
- **Domain:** S3
- **Resource:** `s3://finance-reports-internal`

**Description:** Granting s3:* to account root bypasses normal IAM boundary discipline and is hard to audit.

**Evidence (excerpt):** `{"note": "Principal :root with s3:* detected"}`

**Remediation (summary):** Replace with roles, explicit ARNs, and condition keys (aws:PrincipalArn, vpc SourceIp).

---

#### S3-010 — Default encryption not configured for bucket

- **Severity:** High
- **Domain:** S3
- **Resource:** `s3://vendor-handoff-bucket`

**Description:** Objects may be stored without default SSE-S3 or SSE-KMS at rest.

**Evidence (excerpt):** `{"ServerSideEncryptionConfiguration": null}`

**Remediation (summary):** Enable default bucket encryption; prefer KMS CMK for sensitive data with key policies.

---

#### S3-012 — Default encryption not configured for bucket

- **Severity:** High
- **Domain:** S3
- **Resource:** `s3://deprecated-warehouse`

**Description:** Objects may be stored without default SSE-S3 or SSE-KMS at rest.

**Evidence (excerpt):** `{"ServerSideEncryptionConfiguration": null}`

**Remediation (summary):** Enable default bucket encryption; prefer KMS CMK for sensitive data with key policies.

---

#### SG-003 — Sensitive port exposed to an overly broad CIDR

- **Severity:** High
- **Domain:** SG
- **Resource:** `db-tier-mysql (sg-0f9e8d7c6b5a43210)`

**Description:** Ports [3306] reachable from large network 10.0.0.0/8.

**Evidence (excerpt):** `{"group_id": "sg-0f9e8d7c6b5a43210", "cidr": "10.0.0.0/8"}`

**Remediation (summary):** Narrow to application subnet CIDRs or security group references.

---

#### CT-012 — Burst of AccessDenied errors (possible enumeration)

- **Severity:** Medium
- **Domain:** CloudTrail
- **Resource:** `IAMUser:contractor-analyst`

**Description:** Observed 8 denied API calls within ~2 minutes — often reconnaissance.

**Evidence (excerpt):** `{"window_start": "2026-03-10T18:04:22+00:00", "count": 8}`

**Remediation (summary):** Correlate with GuardDuty; apply SCP denies for s3:ListAllMyBuckets at perimeter if abuse.

---

#### CT-013 — Burst of AccessDenied errors (possible enumeration)

- **Severity:** Medium
- **Domain:** CloudTrail
- **Resource:** `arn:aws:sts::111122223333:assumed-role/CrossAccountVendorRole/automation`

**Description:** Observed 5 denied API calls within ~2 minutes — often reconnaissance.

**Evidence (excerpt):** `{"window_start": "2026-03-12T08:00:00+00:00", "count": 5}`

**Remediation (summary):** Correlate with GuardDuty; apply SCP denies for s3:ListAllMyBuckets at perimeter if abuse.

---

#### IAM-017 — Multiple managed policies attached to a single IAM user

- **Severity:** Medium
- **Domain:** IAM
- **Resource:** `user/svc-legacy-deploy`

**Description:** Users with many attached policies are harder to reason about and often indicate long-lived access.

**Evidence (excerpt):** `{"policies": ["AdministratorAccess-Simulated", "VendorReadOnly"]}`

**Remediation (summary):** Prefer IAM Identity Center groups and permission sets; consolidate and remove redundant policies.

---

#### S3-003 — S3 versioning not enabled

- **Severity:** Medium
- **Domain:** S3
- **Resource:** `s3://corp-public-assets-prod`

**Description:** Without versioning, accidental deletes and ransomware-style overwrites are harder to recover from.

**Evidence (excerpt):** `{"Versioning": {"Status": "Suspended"}}`

**Remediation (summary):** Enable versioning on critical buckets; pair with lifecycle rules and MFA delete for sensitive buckets.

---

#### S3-004 — Server access logging not enabled

- **Severity:** Medium
- **Domain:** S3
- **Resource:** `s3://corp-public-assets-prod`

**Description:** Bucket-level access logging to a dedicated log bucket aids detection and forensics.

**Evidence (excerpt):** `{"Logging": {"LoggingEnabled": false, "TargetBucket": null, "TargetPrefix": null}}`

**Remediation (summary):** Enable server access logging to a centralized logging bucket with tight bucket policy.

---

#### S3-007 — Server access logging not enabled

- **Severity:** Medium
- **Domain:** S3
- **Resource:** `s3://finance-reports-internal`

**Description:** Bucket-level access logging to a dedicated log bucket aids detection and forensics.

**Evidence (excerpt):** `{"Logging": {"LoggingEnabled": false, "TargetBucket": null, "TargetPrefix": null}}`

**Remediation (summary):** Enable server access logging to a centralized logging bucket with tight bucket policy.

---

#### S3-009 — S3 versioning not enabled

- **Severity:** Medium
- **Domain:** S3
- **Resource:** `s3://app-user-uploads-staging`

**Description:** Without versioning, accidental deletes and ransomware-style overwrites are harder to recover from.

**Evidence (excerpt):** `{"Versioning": {"Status": "Suspended"}}`

**Remediation (summary):** Enable versioning on critical buckets; pair with lifecycle rules and MFA delete for sensitive buckets.

---

#### S3-011 — Server access logging not enabled

- **Severity:** Medium
- **Domain:** S3
- **Resource:** `s3://vendor-handoff-bucket`

**Description:** Bucket-level access logging to a dedicated log bucket aids detection and forensics.

**Evidence (excerpt):** `{"Logging": {"LoggingEnabled": false, "TargetBucket": null, "TargetPrefix": null}}`

**Remediation (summary):** Enable server access logging to a centralized logging bucket with tight bucket policy.

---

#### S3-013 — S3 versioning not enabled

- **Severity:** Medium
- **Domain:** S3
- **Resource:** `s3://deprecated-warehouse`

**Description:** Without versioning, accidental deletes and ransomware-style overwrites are harder to recover from.

**Evidence (excerpt):** `{"Versioning": {"Status": "Suspended"}}`

**Remediation (summary):** Enable versioning on critical buckets; pair with lifecycle rules and MFA delete for sensitive buckets.

---

#### S3-014 — Server access logging not enabled

- **Severity:** Medium
- **Domain:** S3
- **Resource:** `s3://deprecated-warehouse`

**Description:** Bucket-level access logging to a dedicated log bucket aids detection and forensics.

**Evidence (excerpt):** `{"Logging": {"LoggingEnabled": false, "TargetBucket": null, "TargetPrefix": null}}`

**Remediation (summary):** Enable server access logging to a centralized logging bucket with tight bucket policy.

---

#### SG-002 — Unrestricted egress (all traffic to 0.0.0.0/0)

- **Severity:** Medium
- **Domain:** SG
- **Resource:** `web-tier-public (sg-0a1b2c3d4e5f67890)`

**Description:** Security group allows all outbound traffic. Often acceptable, but risky for regulated data planes.

**Evidence (excerpt):** `{"group_id": "sg-0a1b2c3d4e5f67890"}`

**Remediation (summary):** For sensitive tiers, restrict egress to required endpoints (VPC endpoints, known IPs).

---

#### SG-004 — Unrestricted egress (all traffic to 0.0.0.0/0)

- **Severity:** Medium
- **Domain:** SG
- **Resource:** `db-tier-mysql (sg-0f9e8d7c6b5a43210)`

**Description:** Security group allows all outbound traffic. Often acceptable, but risky for regulated data planes.

**Evidence (excerpt):** `{"group_id": "sg-0f9e8d7c6b5a43210"}`

**Remediation (summary):** For sensitive tiers, restrict egress to required endpoints (VPC endpoints, known IPs).

---

#### SG-006 — Unrestricted egress (all traffic to 0.0.0.0/0)

- **Severity:** Medium
- **Domain:** SG
- **Resource:** `bastion-legacy (sg-01112233445566778)`

**Description:** Security group allows all outbound traffic. Often acceptable, but risky for regulated data planes.

**Evidence (excerpt):** `{"group_id": "sg-01112233445566778"}`

**Remediation (summary):** For sensitive tiers, restrict egress to required endpoints (VPC endpoints, known IPs).

---

#### SG-008 — Unrestricted egress (all traffic to 0.0.0.0/0)

- **Severity:** Medium
- **Domain:** SG
- **Resource:** `lambda-eni-placeholder (sg-0deadbeefcafe0001)`

**Description:** Security group allows all outbound traffic. Often acceptable, but risky for regulated data planes.

**Evidence (excerpt):** `{"group_id": "sg-0deadbeefcafe0001"}`

**Remediation (summary):** For sensitive tiers, restrict egress to required endpoints (VPC endpoints, known IPs).

---

#### IAM-007 — Potentially unused or stale IAM permissions

- **Severity:** Low
- **Domain:** IAM
- **Resource:** `arn:aws:iam::111122223333:policy/AppRuntimePolicy`

**Description:** Policy 'AppRuntimePolicy' still grants access to resources that appear deprecated.

**Evidence (excerpt):** `{"resource": "arn:aws:s3:::deprecated-warehouse"}`

**Remediation (summary):** Validate last-access; remove unused statements; use IAM Access Analyzer.

---

#### IAM-008 — Potentially unused or stale IAM permissions

- **Severity:** Low
- **Domain:** IAM
- **Resource:** `arn:aws:iam::111122223333:policy/AppRuntimePolicy`

**Description:** Policy 'AppRuntimePolicy' still grants access to resources that appear deprecated.

**Evidence (excerpt):** `{"resource": "arn:aws:s3:::deprecated-warehouse/*"}`

**Remediation (summary):** Validate last-access; remove unused statements; use IAM Access Analyzer.

---

#### SG-007 — Stale or unused security group rule (description hint)

- **Severity:** Low
- **Domain:** SG
- **Resource:** `internal-app-only (sg-09998877665544332)`

**Description:** Rule description suggests the entry is no longer needed.

**Evidence (excerpt):** `{"cidr": "198.51.100.10/32", "description": "unused \u2014 old admin IP", "ports": "22-22"}`

**Remediation (summary):** Review with owners; remove rules quarterly as part of SG hygiene.

---

## Risk matrix (likelihood × impact)

Counts are **heuristic buckets** derived from finding severity (portfolio-friendly, not actuarial).

|  | Impact: High | Impact: Medium |
|--|--------------|----------------|
| **Likelihood: High** | 17 | 0 |
| **Likelihood: Medium** | 21 | 0 |
| **Likelihood: Low** | 0 | 17 |

## Prioritized remediation roadmap

1. **Immediate (0–7 days):** Remove internet-exposed administrative ports; lock down public S3 buckets and Block Public Access; disable root API/console use except break-glass; restore and protect CloudTrail (immutable storage, alerts on `StopLogging`).
2. **Short term (1–4 weeks):** Replace wildcard IAM; remove long-lived superuser on application users; add `sts:ExternalId` and source constraints on vendor roles; enforce MFA for console users.
3. **Medium term (1–3 months):** SCP guardrails, AWS Config rules for S3 public access and SG open ports, centralized logging with Athena queries, quarterly access reviews and IAM Access Analyzer workflows.

## Methodology note

Artifacts were produced by local Python scanners (`scripts/*.py`) over **synthetic JSON** meant to mirror AWS CLI/config exports. This demonstrates **audit workflow and risk framing** rather than live environment discovery.
