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

response = iam.list_users()
users = response["Users"]

for user in users:
    username = user["UserName"]

    keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]

    for key in keys:
        key_id = key["AccessKeyId"]
        created = key["CreateDate"]
        age_days = (now - created).days

        if age_days > FAIL_DAYS:
            decision = "DISABLE"
            status = "FAIL"
        elif age_days > WARN_DAYS:
            decision = "ROTATE"
            status = "WARN"
        else:
            decision = "NONE"
            status = "PASS"

        log_entry = {
            "username": username,
            "access_key": key_id[:4] + "****",
            "age_days": age_days,
            "status": status,
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

# Write remediation log
with open(OUTPUT_FILE, "w") as f:
    json.dump(logs, f, indent=2)

print(f"\nRemediation log written to {OUTPUT_FILE}")
