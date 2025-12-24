import boto3
import csv

from datetime import datetime, timezone

iam = boto3.client("iam")

response = iam.list_users()
users = response["Users"]

for user in users:
    username = user["UserName"]
    print(f"\nUser: {username}")

    keys_response = iam.list_access_keys(UserName=username)
    keys = keys_response["AccessKeyMetadata"]

    if not keys:
        print("  No access keys")
        continue

    for key in keys:
        key_id = key["AccessKeyId"]
        status = key["Status"]
        created = key["CreateDate"]

        age_days = (datetime.now(timezone.utc) - created).days

        print(f"  Key: {key_id}")
        print(f"    Status: {status}")
        print(f"    Age (days): {age_days}")


mfa = iam.list_mfa_devices(UserName=username)
if not mfa["MFADevices"]:
    print("  No MFA devices assigned")
else:
    for device in mfa["MFADevices"]:
        serial = device["SerialNumber"]
        print(f"  MFA Device: {serial}")