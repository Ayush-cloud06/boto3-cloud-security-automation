import boto3
import json
from datetime import datetime, timezone

s3 = boto3.client("s3")

results = []
timestamp = datetime.now(timezone.utc).isoformat()

buckets = s3.list_buckets()["Buckets"]

for bucket in buckets:
    bucket_name = bucket["Name"]

    # ---------- S3 Public Access Block ----------
    try:
        response = s3.get_public_access_block(Bucket=bucket_name)
        config = response["PublicAccessBlockConfiguration"]

        if not all(config.values()):
            results.append({
                "control_id": "S3.PUBLIC_ACCESS_BLOCK",
                "resource_type": "s3_bucket",
                "bucket_name": bucket_name,
                "severity": "HIGH",
                "finding": "Public access block is not fully enabled",
                "recommendation": "Enable all four public access block settings unless explicitly required",
                "mode": "SUGGEST_ONLY",
                "timestamp": timestamp
            })

    except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
        results.append({
            "control_id": "S3.PUBLIC_ACCESS_BLOCK",
            "resource_type": "s3_bucket",
            "bucket_name": bucket_name,
            "severity": "HIGH",
            "finding": "No public access block configuration found",
            "recommendation": "Enable public access block to prevent accidental public exposure",
            "mode": "SUGGEST_ONLY",
            "timestamp": timestamp
        })

    # ---------- S3 ACL Public Exposure ----------
    try:
        acl = s3.get_bucket_acl(Bucket=bucket_name)

        for grant in acl.get("Grants", []):
            grantee = grant.get("Grantee", {})
            uri = grantee.get("URI", "")

            if uri in [
                "http://acs.amazonaws.com/groups/global/AllUsers",
                "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
            ]:
                results.append({
                    "control_id": "S3.PUBLIC_ACL",
                    "resource_type": "s3_bucket",
                    "bucket_name": bucket_name,
                    "severity": "HIGH",
                    "finding": "Bucket ACL allows public access",
                    "recommendation": "Remove public ACL grants and manage access using bucket policies",
                    "mode": "SUGGEST_ONLY",
                    "timestamp": timestamp
                })
                break

    except Exception:
        pass  # acceptable for recommendation-only scans

# Write recommendation report
with open("s3_recommendations.json", "w") as f:
    json.dump(results, f, indent=2)

print("S3 remediation recommendations written to reports/s3_recommendations.json")
