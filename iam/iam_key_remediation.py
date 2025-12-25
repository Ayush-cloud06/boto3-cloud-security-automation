import boto3
import json
from datetime import datetime, timezone

# Configuration

ENFORCE = False   #  Set to True to enforce actions, False for dry-run
WARN_DAYS = 90
FAIL_DAYS = 180

OUTPUT_FILE = "reports/iam_remediation_log.json"

iam = boto3.client("iam")

logs = []
now = datetime.now(timezone.utc)

users = iam.list_users()["Users"]

for user in users:
    username = user["UserName"]
  # Access key check
    keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]

    for key in keys:
        key_id = key["AccessKeyId"]
        created = key["CreateDate"]
        age_days = (now - created).days

        if age_days > FAIL_DAYS:
            decision = "DISABLE"
            status = "FAIL"
            severity = "HIGH"
            reason = f"Access key age exceeds {FAIL_DAYS} days" 

        elif age_days > WARN_DAYS:
            decision = "ROTATE"
            status = "WARN"
            severity = "MEDIUM"
            reason = f"Access key age exceeds {WARN_DAYS} days" 

        else:
            decision = "NONE"
            status = "PASS"
            severity = "LOW"
            reason = "Access key age within compliant limits"



        log_entry = {
            "control_id": "IAM.KEY.ROTATION",
            "username": username,
            "access_key": key_id[:4] + "****",
            "age_days": age_days,
            "status": status,
            "severity": severity,
            "reason": reason,
            "decision": decision,
            "mode": "ENFORCE" if ENFORCE else "DRY-RUN",
            "timestamp": now.isoformat()
        }

        # Controlled action
        if decision == "DISABLE":
            if ENFORCE:
                iam.update_access_key(
                    UserName=username,
                    AccessKeyId=key_id,
                    Status="Inactive"
                )
            else:
                print(f"[DRY-RUN] Would disable key {key_id} for user {username}")

        logs.append(log_entry)

        # MFA check

        try:
            iam.get_login_profile(UserName=username)
            has_console_access = True
        except iam.exceptions.NoSuchEntityException:
            has_console_access = False

            if has_console_access:
                mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]

                if not mfa_devices:
                    logs.append({
                            "control_id": "IAM.MFA.ENFORCEMENT",
                            "username": username,
                            "status": "FAIL",
                            "severity": "HIGH",
                            "decision": "USER_ACTION_REQUIRED",
                            "reason": "Console access without MFA",
                            "mode": "DETECT_ONLY",
                            "timestamp": now.isoformat()
                    })
                else:
                    logs.append({
                        "control_id": "IAM.MFA.ENFORCEMENT",
                        "username": username,
                        "status": "PASS",
                        "severity": "LOW",
                        "decision": "NONE",
                        "reason": "MFA enabled for console access",
                        "mode": "DETECT_ONLY",
                        "timestamp": now.isoformat()
                    })


# Write remediation log
with open(OUTPUT_FILE, "w") as f:
    json.dump(logs, f, indent=2)

print(f"\nRemediation log written to {OUTPUT_FILE}")
