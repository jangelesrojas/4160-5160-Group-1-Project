import boto3

# This file is responsible for actually checking AWS for misconfigurations.
# Each function focuses on one type of issue (S3, IAM, EC2) and returns a list of findings.

def check_s3_public_findings():
    # Connect to AWS S3 using boto3
    s3 = boto3.client("s3")
    findings = []
    
    # Loop through all buckets in the account
    for b in s3.list_buckets().get("Buckets", []):
        name = b["Name"]

        # Check the bucket's ACL for public access
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for g in acl.get("Grants", []):
                grantee = g.get("Grantee", {})
                if grantee.get("URI", "").endswith("AllUsers"):
                    findings.append({
                        "resource": f"s3://{name}",
                        "service": "s3",
                        "issue": "Bucket allows public read via ACL",
                        "severity": "high",
                        "details": {"grant": g}
                    })
                    break
        except Exception:
            # If it fails to get ACL, just skip it (some buckets might be restricted)
            pass

        # Check if there’s a bucket policy that might allow public access
        try:
            pol = s3.get_bucket_policy(Bucket=name)
            findings.append({
                "resource": f"s3://{name}",
                "service": "s3",
                "issue": "Bucket policy may allow public access",
                "severity": "high",
                "details": {"policy": pol.get("Policy", "")}
            })
        except Exception:
            # Not all buckets have a policy, so we just ignore the error
            pass

    return findings


def check_iam_admin_findings():
    # This checks IAM roles that might have overly broad (admin) permissions
    iam = boto3.client("iam")
    findings = []

    paginator = iam.get_paginator("list_roles")
    for page in paginator.paginate():
        for r in page["Roles"]:
            name = r["RoleName"]
            attached = iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]

            # If the role has AdministratorAccess attached, flag it
            if any(p["PolicyName"] == "AdministratorAccess" for p in attached):
                findings.append({
                    "resource": f"iam:role/{name}",
                    "service": "iam",
                    "issue": "Overly broad Admin policy attached",
                    "severity": "medium",
                    "details": {"policies": [p["PolicyName"] for p in attached]}
                })
    return findings


def check_ec2_open_ssh():
    # Checks for EC2 security groups that allow anyone (0.0.0.0/0) to SSH
    ec2 = boto3.client("ec2")
    findings = []
    sgs = ec2.describe_security_groups()["SecurityGroups"]

    for sg in sgs:
        for ip in sg.get("IpPermissions", []):
            if ip.get("FromPort") == 22 and ip.get("ToPort") == 22:
                for rng in ip.get("IpRanges", []):
                    if rng.get("CidrIp") == "0.0.0.0/0":
                        findings.append({
                            "resource": sg["GroupId"],
                            "service": "ec2",
                            "issue": "Security group allows 0.0.0.0/0 on port 22",
                            "severity": "high",
                            "details": {"group_name": sg.get("GroupName")}
                        })
    return findings


def run_collectors():
    # Runs all the above checks and combines their results
    out = []
    out.extend(check_s3_public_findings())
    out.extend(check_iam_admin_findings())
    out.extend(check_ec2_open_ssh())
    return out
