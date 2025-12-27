import boto3
import json
from datetime import datetime, timezone

s3 = boto3.client("s3")

results = []
timestamp = datetime.now(timezone.utc).isoformat()

# List all buckets
buckets = s3.list_buckets()["Buckets"]

for bucket in buckets:
    bucket_name = bucket["Name"]

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
                break  # one finding per bucket is enough

    except Exception as e:
        results.append({
            "control_id": "S3.PUBLIC_ACL",
            "resource_type": "s3_bucket",
            "bucket_name": bucket_name,
            "severity": "UNKNOWN",
            "finding": f"Unable to evaluate bucket ACL: {str(e)}",
            "recommendation": "Manually review bucket ACL permissions",
            "mode": "SUGGEST_ONLY",
            "timestamp": timestamp
        })
# Merged with s3_remediation_recomendation
""" Write recommendation report 
with open("reports/s3_recommendations.json", "w") as f:
    json.dump(results, f, indent=2)

print("S3 ACL remediation recommendations written to reports/s3_recommendations.json")"""
