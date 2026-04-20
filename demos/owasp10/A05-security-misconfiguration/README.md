# OWASP A05:2021 – Security Misconfiguration

## What Is It?

Security Misconfiguration is the most commonly found vulnerability. It occurs when security settings are defined, implemented, or maintained incorrectly — often through overly permissive defaults left in place. In AWS environments this most commonly manifests as:

1. **Wildcard IAM policies** — granting `Action: "*"` on `Resource: "*"` gives any service or principal that assumes the role full control of the entire AWS account
2. **Over-permissive security groups** — opening all ports to `0.0.0.0/0` exposes every service to the internet

## The Demo

| File | Purpose |
|---|---|
| `vulnerable/stack.yaml` | IAM role with God-mode wildcard policy; security group open to world on all ports |
| `fixed/stack.yaml` | Least-privilege IAM role scoped to specific actions and resources; HTTPS-only security group |

## How to Run

> **Warning:** The vulnerable stack creates real AWS resources. Review the template before deploying. Delete the stack immediately after testing.

### Prerequisites

- AWS CLI configured with sufficient permissions to create IAM roles and security groups
- An existing VPC (the security group will be created in the default VPC unless you specify otherwise)

### Vulnerable Stack

```bash
aws cloudformation deploy \
  --template-file vulnerable/stack.yaml \
  --stack-name demo-a05-vulnerable \
  --capabilities CAPABILITY_NAMED_IAM
```

**Inspect the IAM policy:**

```bash
aws iam get-role-policy \
  --role-name InsecureAppRole-Demo \
  --policy-name WildcardEverything
# Shows Action: "*", Resource: "*"
```

**Inspect the security group:**

```bash
aws ec2 describe-security-groups \
  --filters "Name=group-name,Values=VULNERABLE*"
# Shows 0.0.0.0/0 ingress on all ports
```

**Clean up:**

```bash
aws cloudformation delete-stack --stack-name demo-a05-vulnerable
```

### Fixed Stack

```bash
aws cloudformation deploy \
  --template-file fixed/stack.yaml \
  --stack-name demo-a05-fixed \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
      AllowedIngressCidr=10.0.0.0/16 \
      AppBucketArn=arn:aws:s3:::my-app-bucket \
      AppSecretArn=arn:aws:secretsmanager:us-east-1:123456789012:secret:my-creds
```

**Inspect the IAM policy:**

```bash
aws iam get-role-policy \
  --role-name SecureAppRole-Demo \
  --policy-name LeastPrivilegePolicy
# Shows specific actions on specific ARNs only
```

**Clean up:**

```bash
aws cloudformation delete-stack --stack-name demo-a05-fixed
```

## Key Fixes

| Configuration | Vulnerable | Fixed |
|---|---|---|
| IAM `Action` | `"*"` (every AWS API call) | Specific actions only (`s3:GetObject`, `s3:PutObject`, etc.) |
| IAM `Resource` | `"*"` (every resource in account) | Specific ARNs for the app's bucket and secret |
| Security group ports | All ports (0–65535) | Port 443 (HTTPS) only |
| Security group source | `0.0.0.0/0` (entire internet) | Known CIDR range (e.g. `10.0.0.0/16`) |

## References

- [OWASP A05:2021 – Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- [AWS IAM Best Practices — Least Privilege](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege)
- [AWS Security Group Rules Reference](https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules-reference.html)
