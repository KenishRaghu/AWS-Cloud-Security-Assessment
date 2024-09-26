# CloudTrail incident timeline (simulated)

This narrative is derived from the **synthetic** `environment/cloudtrail_logs.json` sample. It is written to mirror how an assessor would **chain events** during an interview walkthrough: reconnaissance noise, privilege/use of roles, defense evasion, and attempted access to sensitive objects.

## Storyline (analyst view)

**Phase A — Access and reconnaissance.** Contractors and standard users sign in from mixed addresses. Several sessions report **console login without MFA**, lowering the bar for session theft. IAM APIs (`ListUsers`, `GetUserPolicy`, `SimulatePrincipalPolicy`) show **repeated AccessDenied** bursts consistent with **enumeration** or tooling probing effective permissions.

**Phase B — Role assumption from unusual networks.** `AssumeRole` appears from **IPs outside the simulated corporate ranges**, including activity against a **cross-account vendor role**. That pattern often indicates **stolen long-lived credentials** or a **confused-deputy** trust that is too loose for the actual caller.

**Phase C — Defense evasion.** A **`StopLogging`** event against the organization trail is a **critical anti-forensics** signal. Even if logging is restarted, the window may have hidden follow-on actions and should trigger **incident response** in a real account.

**Phase D — Data exposure attempt.** **`PutBucketPolicy`** with a **wildcard principal** on a corporate bucket aligns with **making objects readable to the internet**. Subsequent **`GetObject` AccessDenied** bursts against a finance bucket suggest **attempted lateral movement to higher-sensitivity data** that IAM thankfully blocked.

**Phase E — Persistence attempts (blocked).** Rapid **`CreateAccessKey` / `AttachUserPolicy` denials** under the same role session resemble **privilege escalation** attempts that failed due to residual least-privilege on the role — a good outcome, but the attempt still matters for detection tuning.

## Flagged chronological events

| Time (UTC) | Event | Source IP | Principal | Notes |
|------------|-------|-----------|-----------|-------|
| 2026-03-10T08:01:12Z | AssumeRole | 198.51.100.45 | IAMUser:alice.engineer |  |
| 2026-03-10T09:22:41Z | ConsoleLogin | 203.0.113.12 | IAMUser:bob.admin |  |
| 2026-03-10T15:12:33Z | GetObject | 10.0.1.50 | arn:aws:sts::111122223333:assumed-role/EC2-AppRole/i-0abc123 |  |
| 2026-03-10T17:45:11Z | ConsoleLogin | 203.0.113.88 | IAMUser:contractor-analyst | Console login without MFA |
| 2026-03-10T19:00:00Z | AssumeRole | 185.220.101.33 | IAMUser:contractor-analyst | Cross-principal role assumption from unusual IP |
| 2026-03-10T19:02:30Z | GetObject | 185.220.101.33 | arn:aws:sts::111122223333:assumed-role/CrossAccountVendorRole/vendor-sync |  |
| 2026-03-10T22:00:00Z | StopLogging | 185.220.101.33 | arn:aws:sts::111122223333:assumed-role/CrossAccountVendorRole/vendor-sync | Audit log tampering / evasion |
| 2026-03-11T07:30:00Z | ConsoleLogin | 198.51.100.100 | Root | Console login without MFA |
| 2026-03-11T08:00:00Z | GetAccountSummary | 198.51.100.100 | Root | Root activity — break-glass policy violation risk |
| 2026-03-11T08:05:00Z | ListAccountAliases | 198.51.100.100 | Root | Root activity — break-glass policy violation risk |
| 2026-03-11T09:10:00Z | PutBucketPolicy | 185.220.101.33 | arn:aws:sts::111122223333:assumed-role/CrossAccountVendorRole/vendor-sync | Bucket policy change toward public access |
| 2026-03-11T09:45:00Z | DeleteTrail | 185.220.101.33 | arn:aws:sts::111122223333:assumed-role/CrossAccountVendorRole/vendor-sync | Audit log tampering / evasion |
| 2026-03-11T11:00:00Z | AssumeRole | 198.51.100.45 | IAMUser:alice.engineer |  |
| 2026-03-11T13:00:00Z | CreateAccessKey | 185.220.101.33 | arn:aws:sts::111122223333:assumed-role/CrossAccountVendorRole/vendor-sync |  |
| 2026-03-11T13:00:01Z | CreateAccessKey | 185.220.101.33 | arn:aws:sts::111122223333:assumed-role/CrossAccountVendorRole/vendor-sync |  |
| 2026-03-11T13:00:02Z | CreateAccessKey | 185.220.101.33 | arn:aws:sts::111122223333:assumed-role/CrossAccountVendorRole/vendor-sync |  |
| 2026-03-11T14:00:00Z | GetObject | 185.220.101.33 | arn:aws:sts::111122223333:assumed-role/CrossAccountVendorRole/vendor-sync |  |
| 2026-03-11T14:00:01Z | GetObject | 185.220.101.33 | arn:aws:sts::111122223333:assumed-role/CrossAccountVendorRole/vendor-sync |  |
| 2026-03-11T14:00:02Z | GetObject | 185.220.101.33 | arn:aws:sts::111122223333:assumed-role/CrossAccountVendorRole/vendor-sync |  |
| 2026-03-11T16:00:00Z | ConsoleLogin | 198.51.100.12 | IAMUser:bob.admin |  |
| 2026-03-12T07:00:00Z | AssumeRole | 45.33.32.156 | IAMUser:svc-legacy-deploy | Cross-principal role assumption from unusual IP |
| 2026-03-12T09:00:00Z | GetObject | 45.33.32.156 | arn:aws:sts::111122223333:assumed-role/CrossAccountVendorRole/automation |  |
| 2026-03-12T10:00:00Z | ConsoleLogin | 203.0.113.12 | IAMUser:bob.admin |  |
| 2026-03-13T10:00:00Z | ConsoleLogin | 192.0.2.200 | IAMUser:breakglass-emergency | Console login without MFA |

## What to say in an interview

- **Detection:** You would tune alerts for `StopLogging`, `PutBucketPolicy` with public principals, and bursts of `AccessDenied` grouped by principal.
- **Response:** Preserve trail artifacts in immutable storage, pivot on `AssumeRole` session names and access keys, and scope blast radius via S3 policies and SCPs.
- **Prevention:** MFA enforcement, ExternalId on vendor trusts, no admin ports `0.0.0.0/0`, and S3 Block Public Access org-wide.
