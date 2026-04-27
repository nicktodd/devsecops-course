# ============================================================
# Vulnerable Dockerfile - Clair Scanning Demo
# ============================================================
# PURPOSE: Intentionally uses an end-of-life base image and
# outdated packages so that Clair can detect known CVEs.
# DO NOT USE THIS IMAGE IN PRODUCTION.
# ============================================================

# VULNERABILITY 1: Ubuntu 18.04 is End-of-Life (April 2023).
# Its packages contain many unpatched CVEs visible to Clair.
FROM ubuntu:18.04

LABEL maintainer="devsecops-course"
LABEL description="Intentionally vulnerable image for Clair scanning demo"

# VULNERABILITY 2: Installing packages that carry known CVEs in
# the ubuntu:18.04 repositories (openssl, curl, python2.7).
# Clair will match these package versions against NVD/OSV/RHEL
# advisory databases and surface the CVEs.
RUN apt-get update && apt-get install -y \
    curl \
    openssl \
    wget \
    python2.7 \
    && rm -rf /var/lib/apt/lists/*

# VULNERABILITY 3: No USER directive - the container runs as
# root, violating the principle of least privilege.
WORKDIR /app

COPY app.sh .
RUN chmod +x app.sh

# VULNERABILITY 4: No HEALTHCHECK directive.
CMD ["/app/app.sh"]
