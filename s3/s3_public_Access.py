import boto3
from pprint import pprint

# create the client FIRST
s3 = boto3.client("s3")

bucket_name = "ayushcloud.dev"

try:
    response = s3.get_public_access_block(Bucket=bucket_name)
    config = response["PublicAccessBlockConfiguration"]

    pprint(config)

    if all(config.values()):
        print("SECURE: Public access blocked")
    else:
        print("RISK: Public access NOT fully blocked")

except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
    print("RISK: No public access block configured")
