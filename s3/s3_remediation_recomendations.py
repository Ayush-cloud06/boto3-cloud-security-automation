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

    # ---------- S3 Default Encryption ----------
    
    try:
        enc = s3.get_bucket_encryption(Bucket=bucket_name)
        rules = enc.get("ServerSideEncryptionConfiguration")["Rules"]
        algo = rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]

        # Encryption exists -> no findings (secure baseline)

    except s3.exceptions.ClientError as e:

        if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
             results.append({
            "control_id": "S3.ENCRYPTION",
            "resource_type": "s3_bucket",
            "bucket_name": bucket_name,
            "severity": "MEDIUM",
            "finding": "Default encryption is not enabled on the bucket",
            "recommendation": "Enable default encryption using SSE-KMS (preferred) or SSE-S3",
            "mode": "SUGGEST_ONLY",
            "timestamp": timestamp
        })
        else:
            results.append({
                "control_id" : "S3.ENCRYPTION",
                "resource_type" : "s3_bucket",
                "bucket_name" : bucket_name,
                "severity" : "UNKNOWN",
                "finding" : f"Unable to evaluate bucket encryption: {str(e)}",
                "recommendation" : "Manually review bucket encryption configuration",
                "mode" : "SUGGEST_ONLY",
                "timestamp": timestamp  
            })


        # ------ s3 Versioning --------
    
    try:
        versioning = s3.get_bucket_versioning(Bucket=bucket_name)
        status = versioning["Status"]

        if status != "Enabled":
            results.append({ "control_id": "S3.VERSIONING",
            "resource_type": "s3_bucket",
            "bucket_name": bucket_name,
            "severity": "LOW",
            "finding": "Bucket versioning is not enabled",
            "recommendation": "Enable versioning to protect against accidental deletion or overwrite",
            "mode": "SUGGEST_ONLY",
            "timestamp": timestamp
            })

    except Exception as e:
            results.append({ "control_id": "S3.VERSIONING",
            "resource_type": "s3_bucket",
            "bucket_name": bucket_name,
            "severity": "UNKNOWN",
            "finding": f"Unable to evaluate bucket versioning: {str(e)}",
            "recommendation": "Manually review bucket versioning settings",
            "mode": "SUGGEST_ONLY",
            "timestamp": timestamp})

# Write recommendation report
with open("reports/s3_recommendations.json", "w") as f:
    json.dump(results, f, indent=1)

print("S3 remediation recommendations written to reports/s3_recommendations.json")
