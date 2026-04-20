# OWASP A10:2021 – Server-Side Request Forgery (SSRF)

## What Is It?

Server-Side Request Forgery (SSRF) occurs when an application makes an outbound HTTP request to a URL that is fully or partially controlled by an attacker. The key insight is that the **server** makes the request, not the user's browser — so it can reach internal services that the internet cannot.

On AWS this is particularly dangerous because the **Instance Metadata Service (IMDS)** is reachable from inside any EC2 instance at `http://169.254.169.254`. A successful SSRF against an AWS-hosted application can retrieve temporary IAM credentials for the instance's role, potentially granting full control of the AWS account.

## The Demo

| File | Purpose |
|---|---|
| `vulnerable/app.py` | Flask endpoint that fetches any user-supplied URL without restriction |
| `fixed/app.py` | Same endpoint with domain allowlist, blocked IP ranges (including IMDS), HTTPS enforcement, and redirect blocking |

## How to Run

### Prerequisites

```bash
pip install flask requests
```

### Vulnerable Version

```bash
cd vulnerable
python app.py
```

**Reach the AWS IMDS (only works on an EC2 instance — connection refused locally):**

```bash
# Step 1: Discover what metadata is available
curl "http://127.0.0.1:5000/fetch?url=http://169.254.169.254/latest/meta-data/"

# Step 2: Find the IAM role name
curl "http://127.0.0.1:5000/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# Step 3: Retrieve the temporary AWS credentials
curl "http://127.0.0.1:5000/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/MyInstanceRole"
# Returns: { "AccessKeyId": "ASIA...", "SecretAccessKey": "...", "Token": "..." }
# These credentials can now be used with the AWS CLI from anywhere on the internet.
```

**Scan an internal VPC service:**

```bash
curl "http://127.0.0.1:5000/fetch?url=http://10.0.1.100:8080/admin"
```

### Fixed Version

```bash
cd fixed
python app.py
```

**IMDS blocked — 169.254.x.x is in the link-local blocked range:**

```bash
curl "http://127.0.0.1:5000/fetch?url=http://169.254.169.254/latest/meta-data/"
# {"error": "URL not permitted: Only HTTPS URLs are permitted"}
```

**Internal IP blocked:**

```bash
curl "http://127.0.0.1:5000/fetch?url=https://10.0.1.100:8080/admin"
# {"error": "URL not permitted: Domain not in allowlist: 10.0.1.100"}
```

**Unlisted external domain blocked:**

```bash
curl "http://127.0.0.1:5000/fetch?url=https://evil.example.com/steal"
# {"error": "URL not permitted: Domain not in allowlist: evil.example.com"}
```

**Allowlisted domain succeeds:**

```bash
curl "http://127.0.0.1:5000/fetch?url=https://api.example.com/data"
# (proceeds to make the request)
```

## AWS-Specific Mitigation: IMDSv2

In addition to application-level controls, AWS supports **IMDSv2** (Instance Metadata Service v2), which requires a session-oriented token for all metadata requests. This prevents SSRF exploits from reading IMDS even if the application is vulnerable.

Enable IMDSv2 on an existing instance:

```bash
aws ec2 modify-instance-metadata-options \
  --instance-id i-0123456789abcdef0 \
  --http-tokens required \
  --http-endpoint enabled
```

Enforce IMDSv2 in a CloudFormation template:

```yaml
MyInstance:
  Type: AWS::EC2::Instance
  Properties:
    MetadataOptions:
      HttpTokens: required   # Require session token — blocks SSRF
      HttpEndpoint: enabled
```

## Key Fixes

| Issue | Vulnerable | Fixed |
|---|---|---|
| URL validation | None — any URL accepted | Domain allowlist + blocked IP ranges |
| Protocol | HTTP and HTTPS | HTTPS only |
| IMDS reachability | `169.254.169.254` accessible | Blocked (link-local range) |
| Private IPs | Reachable | Blocked (RFC 1918 + loopback) |
| DNS rebinding | Possible | Hostname resolved and IP checked |
| HTTP redirects | Followed automatically | `allow_redirects=False` |
| Error messages | Leaks network topology | Generic "Request failed" |

## References

- [OWASP A10:2021 – Server-Side Request Forgery](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [AWS IMDSv2 — Mitigating SSRF](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
