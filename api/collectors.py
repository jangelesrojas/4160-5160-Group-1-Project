import boto3 

# This file actually talks to AWS (when USE_BOTO=1) to find common misconfigs.
# Each function focuses on one service type and returns a list of "finding" dicts.
# The app's /scan endpoint calls run_collectors() to combine them.

def check_s3_public_findings():
    # Connect to S3
    s3 = boto3.client("s3")
    findings = []
    
    # Loop over all buckets in the account
    for b in s3.list_buckets().get("Buckets", []):
        name = b["Name"]

        # Try to read ACL. If the ACL grants "AllUsers", that means public access via ACL.
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
            # Some buckets might not let us read ACLs (permissions, org policy, etc.), so we skip errors
            pass

        # Also try to read the bucket policy. If it exists, we flag it for review (could be public).
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
            # Many buckets won't have a policy at all; ignore errors here too
            pass

    return findings


def check_iam_admin_findings():
    # Looks for IAM roles with AdministratorAccess attached (over-privileged)
    iam = boto3.client("iam")
    findings = []

    paginator = iam.get_paginator("list_roles")
    for page in paginator.paginate():
        for r in page["Roles"]:
            name = r["RoleName"]
            attached = iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]

            # If AdministratorAccess is attached, we flag it as a medium severity issue
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
    # Finds security groups that allow SSH from the whole internet (0.0.0.0/0 on port 22)
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
    # Runs all the checks and merges the results into one list.
    # /scan will call this if USE_BOTO=1.
    out = []
    out.extend(check_s3_public_findings())
    out.extend(check_iam_admin_findings())
    out.extend(check_ec2_open_ssh())
    return out
