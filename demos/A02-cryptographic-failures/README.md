# OWASP A02:2021 – Cryptographic Failures

## What Is It?

Cryptographic Failures (formerly "Sensitive Data Exposure") covers cases where sensitive data is inadequately protected — either because encryption is absent, or because the cryptographic algorithms used are broken or misapplied. The two most common patterns are:

1. **Broken password hashing** — using fast algorithms (MD5, SHA-1, SHA-256) that were designed for data integrity, not credential storage
2. **Data exposed at rest** — cloud storage (S3 buckets) without encryption, public ACLs, or audit logging

---

## Demo 1 – Password Hashing (Java)

| File | Purpose |
|---|---|
| `vulnerable/PasswordStore.java` | Hashes passwords with MD5 — no salt, instantly crackable |
| `fixed/PasswordStore.java` | Hashes passwords with BCrypt — salted, deliberately slow |

### Prerequisites

Download `jbcrypt-0.4.jar` from Maven Central, or add to `pom.xml`:

```xml
<dependency>
    <groupId>org.mindrot</groupId>
    <artifactId>jbcrypt</artifactId>
    <version>0.4</version>
</dependency>
```

### Run the Vulnerable Version

```bash
cd vulnerable
javac PasswordStore.java
java PasswordStore
```

**Observe:** the MD5 hash `9c87baa223f464954940f859bcf2e233` is always the same for `mypassword123`. Paste it into [crackstation.net](https://crackstation.net) — it cracks in under a second.

### Run the Fixed Version

```bash
cd fixed
javac -cp .:jbcrypt-0.4.jar PasswordStore.java
java  -cp .:jbcrypt-0.4.jar PasswordStore
```

**Observe:** the BCrypt hash changes on every run due to the random embedded salt. Two users with the same password get completely different hashes.

---

## Demo 2 – S3 Bucket Encryption (AWS CloudFormation)

| File | Purpose |
|---|---|
| `vulnerable/s3-bucket.yaml` | Public bucket, no encryption, no logging |
| `fixed/s3-bucket.yaml` | Private, KMS-encrypted, versioned, access-logged |

### Deploy the Vulnerable Stack (review only — do NOT deploy to production)

```bash
aws cloudformation deploy \
  --template-file vulnerable/s3-bucket.yaml \
  --stack-name demo-a02-vulnerable
```

**Observe:** the bucket is publicly accessible. Run:
```bash
aws s3api get-bucket-acl --bucket <bucket-name>
# Shows public read grant
```

### Deploy the Fixed Stack

```bash
aws cloudformation deploy \
  --template-file fixed/s3-bucket.yaml \
  --stack-name demo-a02-fixed \
  --parameter-overrides LogBucketName=<your-log-bucket>
```

**Observe:** all public access is blocked, objects are encrypted with KMS, and all requests are logged.

---

## Key Fixes

| Issue | Vulnerable | Fixed |
|---|---|---|
| Password algorithm | MD5 (fast, broken) | BCrypt (slow, salted, purpose-built) |
| Salt | None — same password = same hash | Unique random salt per hash (embedded) |
| S3 encryption | None | AWS KMS (AES-256) |
| S3 public access | `PublicRead` ACL + open bucket policy | `PublicAccessBlockConfiguration: true` on all settings |
| S3 audit trail | None | Server access logging to separate bucket |
| Transport security | Not enforced | Bucket policy denies HTTP requests |

## References

- [OWASP A02:2021 – Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [AWS S3 Security Best Practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)
