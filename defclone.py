#!/usr/bin/env python3
"""
defclone.py — Extract CVEs from Microsoft Defender for Endpoint by Entra device ID.
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime

import urllib.parse

import requests

API_BASE  = "https://api.securitycenter.microsoft.com"
TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
SCOPE     = "https://api.securitycenter.microsoft.com/.default"

CALLS_PER_MINUTE = 100
CALLS_PER_HOUR   = 1500


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

class RateLimiter:
    def __init__(self):
        self.timestamps = []

    def wait(self):
        now = time.time()
        self.timestamps = [t for t in self.timestamps if now - t < 3600]

        if len(self.timestamps) >= CALLS_PER_HOUR:
            sleep_for = (self.timestamps[0] + 3600) - time.time()
            if sleep_for > 0:
                print(f"Hourly rate limit reached; sleeping {sleep_for:.1f}s ...")
                time.sleep(sleep_for)

        minute_calls = [t for t in self.timestamps if time.time() - t < 60]
        if len(minute_calls) >= CALLS_PER_MINUTE:
            sleep_for = (minute_calls[0] + 60) - time.time()
            if sleep_for > 0:
                print(f"Per-minute rate limit reached; sleeping {sleep_for:.1f}s ...")
                time.sleep(sleep_for)

        self.timestamps.append(time.time())


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

def get_token(tenant_id, client_id, client_secret):
    resp = requests.post(
        TOKEN_URL.format(tenant_id=tenant_id),
        data={
            "client_id":     client_id,
            "client_secret": client_secret,
            "grant_type":    "client_credentials",
            "scope":         SCOPE,
        },
    )
    if resp.status_code != 200:
        print(f"Authentication error: {resp.text}", file=sys.stderr)
        sys.exit(1)
    return resp.json()["access_token"]


# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------

def api_get(session, url, rate_limiter):
    rate_limiter.wait()
    resp = session.get(url)
    if resp.status_code == 401:
        print(f"Authentication error: {resp.text}", file=sys.stderr)
        sys.exit(1)
    resp.raise_for_status()
    return resp.json()


def api_get_all(session, url, rate_limiter):
    """Fetch all pages via @odata.nextLink and return the combined value list."""
    items = []
    while url:
        data = api_get(session, url, rate_limiter)
        items.extend(data.get("value", []))
        url = data.get("@odata.nextLink")
    return items


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Extract CVEs from Microsoft Defender for Endpoint."
    )
    parser.add_argument(
        "--devices", required=True,
        help="Path to file containing Entra device IDs (GUIDs), one per line",
    )
    args = parser.parse_args()

    # Load credentials from environment
    tenant_id     = os.environ.get("AZURE_TENANT_ID")
    client_id     = os.environ.get("AZURE_CLIENT_ID")
    client_secret = os.environ.get("AZURE_CLIENT_SECRET")

    missing = [n for n, v in [
        ("AZURE_TENANT_ID", tenant_id),
        ("AZURE_CLIENT_ID", client_id),
        ("AZURE_CLIENT_SECRET", client_secret),
    ] if not v]
    if missing:
        print(f"Missing required environment variable(s): {', '.join(missing)}", file=sys.stderr)
        sys.exit(1)

    # Load device IDs
    try:
        with open(args.devices) as f:
            device_ids = [ln.strip() for ln in f if ln.strip()]
    except OSError as e:
        print(f"Cannot read devices file: {e}", file=sys.stderr)
        sys.exit(1)

    if not device_ids:
        print("Device list is empty.", file=sys.stderr)
        sys.exit(1)

    token = get_token(tenant_id, client_id, client_secret)

    session = requests.Session()
    session.headers.update({"Authorization": f"Bearer {token}"})

    # Prepare output directory
    ts      = datetime.now().strftime("%Y%m%d-%H%M")
    out_dir = os.path.join("output", ts)
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, f"{ts}-results.json")

    rate_limiter = RateLimiter()
    results = {}

    for entra_id in device_ids:
        print(f"Processing {entra_id} ...")
        try:
            # Resolve Entra device ID -> Defender machine record
            # Build the filter manually — requests percent-encodes '$' in param keys,
            # which the OData API does not accept.
            filter_val = urllib.parse.quote(f"aadDeviceId eq '{entra_id}'")
            machines = api_get_all(
                session,
                f"{API_BASE}/api/machines?$filter={filter_val}",
                rate_limiter,
            )
            if not machines:
                print(f"  No machine found for device ID: {entra_id}")
                continue
            machine     = machines[0]
            defender_id = machine["id"]

            # Per-machine vulnerabilities
            vulns = api_get_all(
                session,
                f"{API_BASE}/api/machines/{defender_id}/vulnerabilities",
                rate_limiter,
            )

            # Logon users
            users = api_get_all(
                session,
                f"{API_BASE}/api/machines/{defender_id}/logonusers",
                rate_limiter,
            )

            results[entra_id] = {
                "machine":         machine,
                "vulnerabilities": vulns,
                "logonUsers":      users,
            }

        except requests.HTTPError as e:
            print(f"  Error for device {entra_id}: {e}")
            continue

    with open(out_file, "w") as f:
        json.dump(results, f, indent=2)

    print(f"Done. Results written to {out_file}")


if __name__ == "__main__":
    main()
