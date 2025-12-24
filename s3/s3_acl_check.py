import boto3
from pprint import pprint


#Check s3 public acces Acl
s3 = boto3.client("s3")
acl = s3.get_bucket_acl(Bucket='ayushcloud.dev')
pprint(acl)

# Check for public grants
for grant in acl["Grants"]:
    print(grant)
