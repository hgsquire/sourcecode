#!/usr/bin/env python3
"""
update_cloud_user_email_from_csv.py

Batch update Atlassian Cloud user emails from a CSV file.

CSV REQUIREMENTS
----------------
- Must contain at least these columns (header names are case-insensitive):
    - current_email
    - new_email

Example CSV:

    current_email,new_email
    old1@example.com,new1@example.com
    old2@example.com,new2@example.com

WHAT THE SCRIPT DOES
--------------------
1. Reads jira_config.ini to select an instance and load:
       url, username, pat, org_api_key

2. For each CSV row:
   - Uses Jira Cloud REST API:
       GET /rest/api/3/user/search?query=<current_email>
     to find the user and obtain the accountId.

   - Uses User management REST API:
       GET  https://api.atlassian.com/users/{account_id}/manage?privileges=email.set
       PUT  https://api.atlassian.com/users/{account_id}/manage/email
     to:
       a) Confirm email.set permission.
       b) Update the user email.

3. Writes a result CSV with:
       current_email, new_email, status, message, account_id, display_name

NOTES
-----
- You MUST be an org admin with a valid org-level User management API key.
- The account must be managed and the new email domain must be in a verified
  domain for your org.
- SCIM/IdP-managed accounts may reject direct email changes via the API.
"""

import argparse
import configparser
import csv
from datetime import datetime
from pathlib import Path
import sys
from typing import Dict, Tuple, Optional

import requests


CONFIG_FILE = "jira_config.ini"


# ---------------------- Config & Instance Selection ---------------------- #

def load_config(config_path: str = CONFIG_FILE) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    if not Path(config_path).is_file():
        raise FileNotFoundError(f"Config file '{config_path}' not found.")
    cfg.read(config_path)
    if not cfg.sections():
        raise RuntimeError(f"No sections found in '{config_path}'.")
    return cfg


def choose_instance(cfg: configparser.ConfigParser) -> str:
    sections = cfg.sections()
    print("Available instances:")
    for idx, sec in enumerate(sections, start=1):
        print(f"{idx}. {sec}")

    choice = input("\nSelect an instance by number: ").strip()
    try:
        idx = int(choice)
        if idx < 1 or idx > len(sections):
            raise ValueError
    except ValueError:
        raise RuntimeError("Invalid instance selection.")

    instance = sections[idx - 1]
    print(f"\nUsing instance [{instance}]")
    return instance


def get_jira_auth_and_url(cfg: configparser.ConfigParser, instance: str) -> Tuple[str, str, str]:
    section = cfg[instance]
    try:
        base_url = section["url"].rstrip("/")
        username = section["username"]
        pat = section["pat"]
    except KeyError as e:
        raise KeyError(
            f"Missing required key {e!r} in section [{instance}] "
            f"(expected: url, username, pat)."
        )
    return base_url, username, pat


def get_org_api_key(cfg: configparser.ConfigParser, instance: str) -> str:
    section = cfg[instance]
    api_key = section.get("org_api_key")
    if not api_key:
        raise KeyError(
            f"'org_api_key' not found in section [{instance}] of {CONFIG_FILE}. "
            f"Add:\n  org_api_key = <your-org-user-management-api-key>"
        )
    return api_key.strip()


# ---------------------- Jira & User Management Helpers ---------------------- #

def jira_find_user_by_email(
    base_url: str,
    username: str,
    pat: str,
    email: str
) -> Dict:
    """
    Find a Jira user by email. Returns the chosen user dict.

    Logic:
        - GET /rest/api/3/user/search?query=<email>
        - First try exact match on emailAddress (case-insensitive).
        - If that fails but there is exactly one result, use that.
        - If multiple ambiguous results remain, raise an error.
    """
    url = f"{base_url}/rest/api/3/user/search"
    params = {"query": email}

    resp = requests.get(url, params=params, auth=(username, pat))
    if resp.status_code != 200:
        raise RuntimeError(
            f"Jira user search failed ({resp.status_code}): {resp.text}"
        )

    users = resp.json()
    if not isinstance(users, list) or not users:
        raise RuntimeError("No users found matching that email/query.")

    # Try strict emailAddress match
    email_lower = email.lower()
    exact_matches = [
        u for u in users
        if str(u.get("emailAddress", "")).lower() == email_lower
    ]

    if len(exact_matches) == 1:
        return exact_matches[0]

    # Fallback: if there was only one result, use it
    if len(users) == 1:
        return users[0]

    # Ambiguous result
    raise RuntimeError(
        f"Multiple users found for '{email}' and no unique emailAddress match."
    )


def check_email_set_permission(org_api_key: str, account_id: str) -> Tuple[bool, str]:
    """
    Check if the org API key has email.set permission for this account.

    Returns (allowed: bool, message: str).
    """
    url = f"https://api.atlassian.com/users/{account_id}/manage"
    params = {"privileges": "email.set"}
    headers = {
        "Authorization": f"Bearer {org_api_key}",
        "Accept": "application/json",
    }

    resp = requests.get(url, headers=headers, params=params)

    if resp.status_code == 404:
        return False, "Account not found via user management API (not in org?)."
    if resp.status_code == 403:
        return False, "Forbidden: org_api_key lacks permission to manage this account."
    if resp.status_code == 401:
        return False, "Unauthorized: org_api_key invalid or expired."
    if resp.status_code != 200:
        return False, f"Permission check failed ({resp.status_code}): {resp.text}"

    data = resp.json()
    email_set = data.get("email.set", {})
    allowed = False

    # "email.set" can be a boolean or an object with details; be liberal here.
    if isinstance(email_set, bool):
        allowed = email_set
    elif isinstance(email_set, dict):
        # Some shapes have 'allowed' or nested objects
        if email_set.get("allowed") is True:
            allowed = True
        else:
            for v in email_set.values():
                if isinstance(v, dict) and v.get("allowed") is True:
                    allowed = True
                    break

    if allowed:
        return True, "email.set permission allowed."
    else:
        return False, "email.set permission NOT allowed for this account."


def set_user_email(org_api_key: str, account_id: str, new_email: str) -> Tuple[bool, str]:
    """
    Call User management REST API to update the email address:

        PUT https://api.atlassian.com/users/{account_id}/manage/email
        Body: {"email": "<new_email>"}

    Returns (success: bool, message: str).
    """
    url = f"https://api.atlassian.com/users/{account_id}/manage/email"
    headers = {
        "Authorization": f"Bearer {org_api_key}",
        "Content-Type": "application/json",
    }
    payload = {"email": new_email}

    resp = requests.put(url, headers=headers, json=payload)

    if resp.status_code == 204:
        return True, "Email updated; active sessions invalidated."

    if resp.status_code == 400:
        msg = (
            "400 Bad Request – possible causes: "
            "unverified domain, email already in use, or SCIM/IdP-managed account."
        )
    elif resp.status_code == 401:
        msg = "401 Unauthorized – org_api_key invalid or expired."
    elif resp.status_code == 403:
        msg = "403 Forbidden – org_api_key lacks 'email.set' or not allowed for this user."
    elif resp.status_code == 404:
        msg = "404 Not Found – account not visible in this organization."
    else:
        msg = f"Unexpected status code {resp.status_code}: {resp.text}"

    return False, msg + f" Raw response: {resp.text}"


# ---------------------- CSV Handling ---------------------- #

def normalize_header_map(headers) -> Dict[str, str]:
    """
    Build a mapping from lowercased header name to original header name.
    """
    return {h.strip().lower(): h for h in headers}


def process_csv(
    csv_path: Path,
    base_url: str,
    jira_user: str,
    jira_pat: str,
    org_api_key: str
) -> Path:
    """
    Process the input CSV and return the path to the result CSV.
    """

    if not csv_path.is_file():
        raise FileNotFoundError(f"CSV file '{csv_path}' not found.")

    print(f"\nReading CSV: {csv_path}")

    with csv_path.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise RuntimeError("Input CSV has no header row.")

        header_map = normalize_header_map(reader.fieldnames)

        if "current_email" not in header_map or "new_email" not in header_map:
            raise RuntimeError(
                "CSV must contain 'current_email' and 'new_email' columns "
                "(header names are case-insensitive)."
            )

        current_email_col = header_map["current_email"]
        new_email_col = header_map["new_email"]

        rows = list(reader)

    if not rows:
        raise RuntimeError("Input CSV has no data rows.")

    # Prepare result CSV path
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    result_path = csv_path.with_name(
        f"{csv_path.stem}_results_{timestamp}{csv_path.suffix}"
    )

    print(f"\nProcessing {len(rows)} rows...")
    print(f"Results will be written to: {result_path}")

    # Open result CSV
    fieldnames = [
        "current_email",
        "new_email",
        "status",
        "message",
        "account_id",
        "display_name",
    ]

    success_count = 0
    fail_count = 0

    with result_path.open("w", newline="", encoding="utf-8") as f_out:
        writer = csv.DictWriter(f_out, fieldnames=fieldnames)
        writer.writeheader()

        for idx, row in enumerate(rows, start=1):
            current_email = (row.get(current_email_col) or "").strip()
            new_email = (row.get(new_email_col) or "").strip()

            result: Dict[str, Optional[str]] = {
                "current_email": current_email,
                "new_email": new_email,
                "status": "FAIL",
                "message": "",
                "account_id": "",
                "display_name": "",
            }

            print(f"\n[{idx}/{len(rows)}] {current_email} -> {new_email}")

            if not current_email or not new_email:
                result["message"] = "Missing current_email or new_email."
                writer.writerow(result)
                fail_count += 1
                print("  Skipped: missing email values.")
                continue

            if current_email.lower() == new_email.lower():
                result["message"] = "Current and new email are identical; no change."
                result["status"] = "SKIP"
                writer.writerow(result)
                print("  Skipped: identical emails.")
                continue

            try:
                # 1) Find user in Jira
                user = jira_find_user_by_email(base_url, jira_user, jira_pat, current_email)
                account_id = user.get("accountId") or ""
                display_name = user.get("displayName") or ""

                result["account_id"] = account_id
                result["display_name"] = display_name

                if not account_id:
                    raise RuntimeError("User found but has no accountId; cannot update.")

                print(f"  Found user: {display_name} (accountId={account_id})")

                # 2) Check email.set permission
                allowed, perm_msg = check_email_set_permission(org_api_key, account_id)
                print(f"  Permission check: {perm_msg}")
                if not allowed:
                    result["message"] = f"Permission denied: {perm_msg}"
                    writer.writerow(result)
                    fail_count += 1
                    continue

                # 3) Update email
                success, msg = set_user_email(org_api_key, account_id, new_email)
                print(f"  Update result: {msg}")

                if success:
                    result["status"] = "SUCCESS"
                    result["message"] = msg
                    success_count += 1
                else:
                    result["message"] = msg
                    fail_count += 1

            except Exception as e:
                # Catch all per-row errors so the batch keeps going
                result["message"] = f"Exception: {e}"
                fail_count += 1
                print(f"  ERROR: {e}")

            writer.writerow(result)

    print("\nBatch complete.")
    print(f"  Success: {success_count}")
    print(f"  Failed : {fail_count}")
    print(f"Result CSV: {result_path}")

    return result_path


# ---------------------- Main ---------------------- #

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Batch update Atlassian Cloud user emails from a CSV file."
    )
    p.add_argument(
        "csv_path",
        help="Path to the input CSV containing current_email and new_email columns.",
    )
    return p.parse_args()


def main():
    args = parse_args()
    csv_path = Path(args.csv_path)

    try:
        cfg = load_config()
        instance = choose_instance(cfg)
        base_url, jira_user, jira_pat = get_jira_auth_and_url(cfg, instance)
        org_api_key = get_org_api_key(cfg, instance)

        process_csv(csv_path, base_url, jira_user, jira_pat, org_api_key)

    except Exception as e:
        print(f"\nFATAL ERROR: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
