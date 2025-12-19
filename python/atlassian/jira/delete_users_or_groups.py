#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Delete Users or Groups from CSV (Org-aware, nested-prefix, flexible auth, BOM-safe)
-----------------------------------------------------------------------------------
- Choose Users or Groups deletion from CSV.
- Users:
  * Resolve accountId via Admin (Org) API search by email (preferred), then Jira user search.
  * Remove from all Jira groups.
  * Best-effort Org deactivation (if Admin creds available).
- Groups:
  * Delete groups by name.
- Config (matches user's INI):
  * Env sections: url, pat, optional username (or email), optional auth_scheme (basic|bearer).
    - If auth_scheme is omitted: inferred as 'basic' when username/email present, else 'bearer'.
  * Admin sections: org_id, api_key, optional base_admin_api (default: https://api.atlassian.com).
  * Admin section selection order:
      1) env's admin_section (if present),
      2) nested prefixes (longest → shortest): e.g., SDE_EU_Prod → SDE_EU_Atlassian_Admin → SDE_Atlassian_Admin,
      3) global fallback: Atlassian_Admin.
  * Matching is case-insensitive, whitespace-tolerant, and removes zero-width/BOM chars.
- Logging: console + delete_users_or_groups.log with extra diagnostics.
- Python: 3.10+ (tested on 3.12.x)
"""

import csv
import sys
import time
import logging
import configparser
import re
from pathlib import Path
from typing import Optional, Tuple, Dict, Any, List

import requests
from requests.adapters import HTTPAdapter, Retry
requests.packages.urllib3.disable_warnings()  # Suppress SSL warnings (self-signed)

# --------------------------
# Logging
# --------------------------
LOG_FILE = Path("delete_users_or_groups.log")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_FILE, mode="w", encoding="utf-8")
    ],
)

# --------------------------
# Interactive helpers
# --------------------------
def prompt_choice(prompt: str, options: List[str]) -> str:
    opt_str = ", ".join(f"[{i+1}] {opt}" for i, opt in enumerate(options))
    while True:
        print(f"{prompt} {opt_str}")
        choice = input("> ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(options):
            return options[int(choice) - 1]
        for opt in options:
            if choice.lower() == opt.lower():
                return opt
        print("Invalid choice. Try again.\n")


def input_nonempty(prompt: str) -> str:
    while True:
        val = input(prompt).strip()
        if val:
            return val
        print("A value is required. Try again.\n")

# --------------------------
# Normalization helpers
# --------------------------
_ZW_CHARS = "".join([
    "\ufeff",  # BOM
    "\u200b",  # ZERO WIDTH SPACE
    "\u200c",  # ZERO WIDTH NON-JOINER
    "\u200d",  # ZERO WIDTH JOINER
    "\u2060",  # WORD JOINER
])

def strip_invisibles(s: str) -> str:
    if s is None:
        return ""
    return s.translate({ord(c): None for c in _ZW_CHARS}).strip()

def norm_section_key(s: str) -> str:
    # Case-insensitive, trim, remove zero-width/BOM, normalize underscores
    s = strip_invisibles(s)
    s = re.sub(r"\s+", " ", s)
    s = re.sub(r"\s*_\s*", "_", s)
    return s.lower()

# --------------------------
# Session / Config
# --------------------------
def build_session() -> requests.Session:
    session = requests.Session()
    retries = Retry(
        total=5,
        backoff_factor=0.6,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "POST", "PUT", "PATCH", "DELETE"])
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session

def read_config(path: Path) -> configparser.ConfigParser:
    if not path.exists():
        logging.error(f"Config file not found: {path.resolve()}")
        sys.exit(1)
    raw = path.read_text(encoding="utf-8", errors="replace")
    cleaned = strip_invisibles(raw)
    cfg = configparser.ConfigParser()
    cfg.read_string(cleaned)
    return cfg

def detect_env_sections(cfg: configparser.ConfigParser) -> List[str]:
    """Environment sections = any section that contains 'url' key."""
    envs = []
    for s in cfg.sections():
        if cfg.has_option(s, "url"):
            envs.append(s)
    return envs

# --------------------------
# Admin section resolution
# --------------------------
def admin_section_candidates(env_section: str) -> List[str]:
    """
    Generate nested admin section candidates from an environment section.
      'SDE_EU_Prod' -> ['SDE_EU_Atlassian_Admin', 'SDE_Atlassian_Admin', 'Atlassian_Admin']
      'SDE_Prod'    -> ['SDE_Atlassian_Admin', 'Atlassian_Admin']
      'Prod'        -> ['Atlassian_Admin']
    """
    parts = [p for p in strip_invisibles(env_section).split("_") if p]
    candidates: List[str] = []
    if len(parts) > 1:
        for i in range(len(parts) - 1, 0, -1):
            prefix = "_".join(parts[:i]) + "_"
            candidates.append(f"{prefix}Atlassian_Admin")
    candidates.append("Atlassian_Admin")
    return candidates

def select_admin_section(cfg: configparser.ConfigParser, env_section: str) -> Optional[str]:
    """
    Case-insensitive, whitespace- & zero-width-safe selection.
    Prefer the first existing candidate; otherwise None.
    """
    normalized_map = {norm_section_key(s): s for s in cfg.sections()}
    for cand in admin_section_candidates(env_section):
        key = norm_section_key(cand)
        if key in normalized_map:
            return normalized_map[key]
    return None

# --------------------------
# Option helpers
# --------------------------
def require_option(cfg: configparser.ConfigParser, section: str, option: str) -> str:
    if not cfg.has_option(section, option):
        logging.error(f"Missing option '{option}' in section [{section}]")
        sys.exit(1)
    return strip_invisibles(cfg.get(section, option))

def build_jira_headers(cfg: configparser.ConfigParser, env: str) -> Dict[str, str]:
    """
    Builds Jira auth headers based on env-auth settings:
      - If auth_scheme is set: use it (basic|bearer).
      - If auth_scheme is omitted: infer 'basic' when username/email present; else 'bearer'.
      - basic: needs username (or email) + pat; sends Basic base64(username:pat)
      - bearer: uses 'pat' as Bearer token
    """
    pat = require_option(cfg, env, "pat")
    # Infer scheme if omitted
    scheme = strip_invisibles(cfg.get(env, "auth_scheme", fallback="")).lower()
    has_user = cfg.has_option(env, "username") or cfg.has_option(env, "email")
    if not scheme:
        scheme = "basic" if has_user else "bearer"

    if scheme == "basic":
        # Support either 'username' or 'email'
        user = (cfg.get(env, "username", fallback="").strip()
                or cfg.get(env, "email", fallback="").strip())
        if not user:
            logging.error(f"[{env}] auth_scheme=basic requires 'username' or 'email'.")
            sys.exit(1)
        import base64
        token = base64.b64encode(f"{user}:{pat}".encode("utf-8")).decode("utf-8")
        logging.info(f"[{env}] Using BASIC auth with user '{user}'.")
        return {"Authorization": f"Basic {token}", "Accept": "application/json", "Content-Type": "application/json"}

    logging.info(f"[{env}] Using BEARER auth.")
    return {"Authorization": f"Bearer {pat}", "Accept": "application/json", "Content-Type": "application/json"}

def admin_auth_headers(api_key: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

# --------------------------
# Admin (Org) API helpers
# --------------------------
def admin_search_user_by_email(session: requests.Session, base_admin_api: str, org_id: str,
                               email: str, headers: Dict[str, str]) -> Optional[Dict[str, Any]]:
    url = f"{base_admin_api.rstrip('/')}/admin/v1/orgs/{org_id}/users/search"
    payload = {"query": email}
    try:
        r = session.post(url, headers=headers, json=payload, timeout=30, verify=False)
        if r.status_code == 200:
            data = r.json()
            if isinstance(data, dict) and data.get("data"):
                for u in data["data"]:
                    if (u.get("email") or "").lower() == email.lower():
                        return u
                return data["data"][0]
            if isinstance(data, list) and data:
                for u in data:
                    if (u.get("email") or "").lower() == email.lower():
                        return u
                return data[0]
            return None
        else:
            logging.warning(f"Admin search non-200 for {email}: {r.status_code} {r.text[:300]}")
            return None
    except Exception as e:
        logging.error(f"Admin search error for {email}: {e}")
        return None

def admin_attempt_deactivate_user(session: requests.Session, base_admin_api: str, org_id: str,
                                  account_id: str, headers: Dict[str, str], test_mode: bool) -> Tuple[bool, str]:
    url_candidates = [
        f"{base_admin_api.rstrip('/')}/admin/v1/orgs/{org_id}/users/{account_id}/status",     # PATCH {"status": "inactive"}
        f"{base_admin_api.rstrip('/')}/admin/v1/orgs/{org_id}/users/{account_id}/deactivate"  # POST
    ]
    for url in url_candidates:
        try:
            if test_mode:
                return True, f"(test) Would attempt org deactivation at: {url}"
            if url.endswith("/status"):
                r = session.patch(url, headers=headers, json={"status": "inactive"}, timeout=30, verify=False)
            else:
                r = session.post(url, headers=headers, timeout=30, verify=False)
            if r.status_code in (200, 202, 204):
                return True, f"Deactivation requested via {url} (HTTP {r.status_code})"
            else:
                logging.warning(f"Deactivation attempt failed via {url}: {r.status_code} {r.text[:300]}")
        except Exception as e:
            logging.warning(f"Deactivation exception at {url}: {e}")
    return False, "Org deactivation not permitted/available; user removed from Jira groups instead."

# --------------------------
# Jira API helpers
# --------------------------
def jira_find_user_by_email(session: requests.Session, jira_url: str, email: str,
                            headers: Dict[str, str]) -> Optional[Dict[str, Any]]:
    url = f"{jira_url.rstrip('/')}/rest/api/3/user/search"
    params = {"query": email}
    try:
        r = session.get(url, headers=headers, params=params, timeout=30, verify=False)
        if r.status_code == 200:
            users = r.json()
            if users:
                for u in users:
                    if (u.get("emailAddress") or "").lower() == email.lower():
                        return u
                return users[0]
            return None
        else:
            logging.warning(f"Jira user search non-200 for {email}: {r.status_code} {r.text[:300]}")
            return None
    except Exception as e:
        logging.error(f"Jira user search error for {email}: {e}")
        return None

def jira_get_user_groups(session: requests.Session, jira_url: str, account_id: str,
                         headers: Dict[str, str]) -> List[str]:
    url = f"{jira_url.rstrip('/')}/rest/api/3/user/groups"
    params = {"accountId": account_id}
    try:
        r = session.get(url, headers=headers, params=params, timeout=30, verify=False)
        if r.status_code == 200:
            groups = r.json()
            return [g.get("name") for g in groups if g.get("name")]
        else:
            logging.warning(f"Get user groups non-200 for {account_id}: {r.status_code} {r.text[:300]}")
            return []
    except Exception as e:
        logging.error(f"Get user groups error for {account_id}]: {e}")
        return []

def jira_remove_user_from_group(session: requests.Session, jira_url: str, groupname: str,
                                account_id: str, headers: Dict[str, str], test_mode: bool) -> Tuple[bool, str]:
    url = f"{jira_url.rstrip('/')}/rest/api/3/group/user"
    params = {"groupname": groupname, "accountId": account_id}
    try:
        if test_mode:
            return True, f"(test) Would remove user {account_id} from group '{groupname}'"
        r = session.delete(url, headers=headers, params=params, timeout=30, verify=False)
        if r.status_code in (200, 204):
            return True, f"Removed from group '{groupname}'"
        else:
            return False, f"Failed to remove from '{groupname}': {r.status_code} {r.text[:200]}"
    except Exception as e:
        return False, f"Exception removing from '{groupname}': {e}"

def jira_delete_group(session: requests.Session, jira_url: str, groupname: str,
                      headers: Dict[str, str], test_mode: bool) -> Tuple[bool, str]:
    url = f"{jira_url.rstrip('/')}/rest/api/3/group"
    params = {"groupname": groupname}
    try:
        if test_mode:
            return True, f"(test) Would delete group '{groupname}'"
        r = session.delete(url, headers=headers, params=params, timeout=30, verify=False)
        if r.status_code in (200, 204):
            return True, f"Deleted group '{groupname}'"
        elif r.status_code == 400 and "not empty" in r.text.lower():
            return False, f"Cannot delete group '{groupname}': Group not empty or is a default/bound group."
        else:
            return False, f"Failed to delete '{groupname}': {r.status_code} {r.text[:200]}"
    except Exception as e:
        return False, f"Exception deleting '{groupname}': {e}"

# --------------------------
# Workflows
# --------------------------
def delete_user_workflow(session: requests.Session,
                         jira_url: str,
                         jira_headers: Dict[str, str],
                         admin_cfg: Optional[Dict[str, str]],
                         csv_path: Path,
                         test_mode: bool) -> None:
    if not csv_path.exists():
        logging.error(f"Users CSV not found: {csv_path.resolve()}")
        sys.exit(1)

    admin_details = None
    if admin_cfg:
        admin_details = {
            "base_admin_api": admin_cfg["base_admin_api"],
            "org_id": admin_cfg["org_id"],
            "headers": admin_auth_headers(admin_cfg["api_key"])
        }

    with csv_path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        headers = [strip_invisibles(h).lower() for h in (reader.fieldnames or [])]
        if "email" not in headers and "accountid" not in headers:
            logging.error("Users CSV must have 'email' or 'accountId' column.")
            sys.exit(1)

        processed = 0
        for row in reader:
            processed += 1
            email = strip_invisibles(row.get("email") or row.get("Email") or "")
            account_id = strip_invisibles(row.get("accountId") or row.get("AccountId") or "")

            resolved_user = None
            if email:
                if admin_details:
                    u = admin_search_user_by_email(
                        session,
                        admin_details["base_admin_api"],
                        admin_details["org_id"],
                        email,
                        admin_details["headers"]
                    )
                    if u:
                        aid = u.get("account_id") or u.get("accountId") or u.get("id")
                        if aid:
                            resolved_user = {"accountId": aid, "emailAddress": u.get("email") or email}
                if not resolved_user:
                    ju = jira_find_user_by_email(session, jira_url, email, jira_headers)
                    if ju:
                        resolved_user = ju
            elif account_id:
                resolved_user = {"accountId": account_id}

            if not resolved_user or not resolved_user.get("accountId"):
                logging.warning(f"[{processed}] Could not resolve user -> email='{email}' accountId='{account_id}'")
                continue

            aid = resolved_user["accountId"]
            logging.info(f"[{processed}] Processing user accountId={aid} email={email or resolved_user.get('emailAddress','')}")

            groups = jira_get_user_groups(session, jira_url, aid, jira_headers)
            if not groups:
                logging.info(f"  No groups found for {aid}")
            else:
                for g in groups:
                    ok, msg = jira_remove_user_from_group(session, jira_url, g, aid, jira_headers, test_mode)
                    logging.info(f"  {msg}")

            if admin_details:
                ok, msg = admin_attempt_deactivate_user(
                    session,
                    admin_details["base_admin_api"],
                    admin_details["org_id"],
                    aid,
                    admin_details["headers"],
                    test_mode
                )
                logging.info(f"  Org deactivation: {msg}")
            else:
                logging.info("  Org deactivation skipped (no matching admin section found).")

            time.sleep(0.2)

        logging.info(f"User deletion workflow complete. Processed rows: {processed}")

def delete_groups_workflow(session: requests.Session,
                           jira_url: str,
                           jira_headers: Dict[str, str],
                           csv_path: Path,
                           test_mode: bool) -> None:
    if not csv_path.exists():
        logging.error(f"Groups CSV not found: {csv_path.resolve()}")
        sys.exit(1)

    with csv_path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        headers = [strip_invisibles(h).lower() for h in (reader.fieldnames or [])]
        if "groupname" not in headers:
            logging.error("Groups CSV must have a 'groupname' column.")
            sys.exit(1)

    processed = 0
    with csv_path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            processed += 1
            groupname = strip_invisibles(row.get("groupname") or row.get("GroupName") or "")
            if not groupname:
                logging.warning(f"[{processed}] Skipping blank groupname.")
                continue

            ok, msg = jira_delete_group(session, jira_url, groupname, jira_headers, test_mode)
            logging.info(f"[{processed}] {msg}")
            time.sleep(0.15)

    logging.info(f"Group deletion workflow complete. Processed rows: {processed}")

# --------------------------
# Main
# --------------------------
def main():
    print("\n=== Delete Users or Groups from CSV (Org-aware, nested-prefix, flexible auth, BOM-safe) ===\n")

    cfg_path = Path(input_nonempty("Path to jira_config.ini (e.g., ./jira_config.ini): "))
    cfg = read_config(cfg_path)

    # Log normalized map so you can see what was recognized
    norm_map = {norm_section_key(s): s for s in cfg.sections()}
    logging.info(f"Loaded sections (raw): {cfg.sections()}")
    logging.info(f"Loaded sections (normalized→raw): {norm_map}")

    env_sections = detect_env_sections(cfg)
    if not env_sections:
        logging.error("No environment sections found (need sections with 'url').")
        sys.exit(1)

    chosen_env = prompt_choice("Select environment section:", env_sections)
    logging.info(f"Admin candidates for {chosen_env}: {admin_section_candidates(chosen_env)}")

    # Jira connection/auth
    jira_url = require_option(cfg, chosen_env, "url")
    jira_headers = build_jira_headers(cfg, chosen_env)

    # Admin/Org details
    override = strip_invisibles(cfg.get(chosen_env, "admin_section", fallback=""))
    if override:
        if not cfg.has_section(override):
            logging.error(f"admin_section override '{override}' not found in ini.")
            sys.exit(1)
        admin_section = override
        logging.info(f"Using admin_section override: [{admin_section}]")
    else:
        admin_section = select_admin_section(cfg, chosen_env)

    admin_cfg = None
    if admin_section:
        base_admin_api = strip_invisibles(cfg.get(admin_section, "base_admin_api", fallback="https://api.atlassian.com"))
        org_id = require_option(cfg, admin_section, "org_id")
        api_key = require_option(cfg, admin_section, "api_key")
        admin_cfg = {"base_admin_api": base_admin_api, "org_id": org_id, "api_key": api_key}
        logging.info(f"Matched admin section: [{admin_section}] for environment [{chosen_env}]")
    else:
        tried = admin_section_candidates(chosen_env)
        logging.warning(f"No matching admin section for [{chosen_env}] (tried {tried}). "
                        f"Org API calls will be skipped. "
                        f"Consider adding 'admin_section = <Your_Admin_Section>' under [{chosen_env}].")

    # Mode selection
    mode = prompt_choice("What would you like to delete from CSV?", ["Users", "Groups"])
    csv_path = Path(input_nonempty(f"Path to the {mode.lower()} CSV: "))
    test_mode_answer = prompt_choice("Run in test (dry-run) mode?", ["Yes", "No"])
    test_mode = (test_mode_answer.lower() == "yes")

    session = build_session()

    if mode.lower() == "users":
        delete_user_workflow(session, jira_url, jira_headers, admin_cfg, csv_path, test_mode)
    else:
        delete_groups_workflow(session, jira_url, jira_headers, csv_path, test_mode)

    print("\nDone. See log:", LOG_FILE.resolve())

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nCancelled by user.")
