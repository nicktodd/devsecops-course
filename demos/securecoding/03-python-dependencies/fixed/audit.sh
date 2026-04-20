#!/usr/bin/env bash
# Dependency vulnerability audit script.
#
# Scans the pinned requirements.txt for packages with known CVEs using pip-audit.
# Intended for use as a CI gate: the build fails (exit code 1) if any
# vulnerability is found, preventing deployment of affected code.
#
# Usage:
#   chmod +x audit.sh
#   ./audit.sh
#
# CI integration (GitHub Actions / Jenkins):
#   - Run this script as a build step.
#   - A non-zero exit code will fail the pipeline.
#
# Prerequisites:
#   pip install pip-audit

set -euo pipefail

REQUIREMENTS="requirements.txt"

echo "=== Dependency Vulnerability Audit ==="
echo "Scanning: $REQUIREMENTS"
echo

# pip-audit checks each pinned package against the OSV and PyPA advisory databases.
# --require-hashes: verifies SHA-256 hashes match (integrity check, not just CVE scan).
# --strict:         treats warnings as errors (e.g. packages with no vulnerability data).
if pip-audit --require-hashes -r "$REQUIREMENTS"; then
    echo
    echo "PASS: No known vulnerabilities detected."
    exit 0
else
    echo
    echo "FAIL: Vulnerable dependencies found."
    echo "      Review the output above, update requirements.in, and regenerate:"
    echo "        pip-compile --generate-hashes requirements.in"
    exit 1
fi

# Alternative: use 'safety' (pip install safety):
#   safety check -r "$REQUIREMENTS" --full-report
