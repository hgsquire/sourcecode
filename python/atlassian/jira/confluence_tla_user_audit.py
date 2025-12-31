#!/usr/bin/env python3
r"""
confluence_tla_user_audit.py

Confluence Cloud (Enterprise) - TLA user audit for a space and all pages, with enrichment map.

What it does
- Reads Confluence Cloud base URL + credentials from jira_config.ini
- Prompts for Confluence space key (e.g., VISO)
- Loads input users from VUMC-vec-users.xlsx (preferred) OR VUMC-vec-users.csv (fallback) in the same directory
- Builds an enrichment map keyed by:
    * VUMC ID Email
    * TLA Email
    * username extracted from "Name (VUMC ID)" parentheses
    * full "Name (VUMC ID)" string
- Crawls all pages in the space and records users who:
    * contain substring "tla" in identity strings, OR
    * match any identifier from input file (email/name/username/accountId)

Sources checked
- Space permissions (best-effort)
- Page restrictions: read/update users
- Page author (createdBy)
- Page last modifier (version.by)

Admin Key support (Enterprise)
- Optional flag: --admin-key
- The script will ENABLE Admin Key via REST v2 (wiki/api/v2/admin-key),
  then include header Atl-Confluence-With-Admin-Key: true on all REST calls.
  This is required; sending the header alone does not activate Admin Key.
  NOTE: Your account must be eligible to use Admin Key.

Output
- CSV audit log: confluence_tla_audit_<SPACEKEY>_<timestamp>.csv
- Adds a run_summary row at the end with coverage numbers

Dependencies
- requests
- Optional for XLSX: pandas + openpyxl

Install
  python -m pip install requests
  python -m pip install pandas openpyxl

Examples
  python .\confluence_tla_user_audit.py
  python .\confluence_tla_user_audit.py --admin-key --section VUMC_Cloud --space VISO
"""

import argparse
import csv
import datetime
import os
import re
import sys
import time
import configparser
from typing import Dict, Any, List, Optional, Tuple

import requests
from requests.auth import HTTPBasicAuth

# Optional dependency only needed for XLSX
try:
    import pandas as pd  # type: ignore
except Exception:
    pd = None


# Defaults
DEFAULT_INI = "jira_config.ini"
INPUT_XLSX = "VUMC-vec-users.xlsx"
INPUT_CSV = "VUMC-vec-users.csv"

TLA_SUBSTRING = "tla"
PAGE_FETCH_LIMIT = 100
REQUEST_TIMEOUT = 60


def script_dir() -> str:
    return os.path.dirname(os.path.abspath(__file__))


def now_stamp() -> str:
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")


def norm(s: Optional[str]) -> str:
    return (s or "").strip().lower()


def safe_get(d: Dict[str, Any], *keys, default=None):
    cur = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur


def normalize_confluence_base_url(url: str) -> str:
    """
    Confluence Cloud REST APIs are typically under:
      https://<site>.atlassian.net/wiki/rest/api/...

    Ensure base ends with /wiki (no trailing slash).
    """
    u = (url or "").strip().rstrip("/")
    if not u:
        return u
    if u.endswith("/wiki"):
        return u
    return u + "/wiki"


def extract_username_from_name_field(name_field: str) -> str:
    """
    Example: 'Anderson, Jason R (anderjr2)' -> 'anderjr2'
    """
    m = re.search(r"\(([^)]+)\)\s*$", name_field or "")
    return m.group(1).strip() if m else ""


def build_enrichment_map_from_dataframe(df) -> Dict[str, Dict[str, str]]:
    cols = {str(c).strip().lower(): c for c in df.columns}

    name_col = cols.get("name (vumc id)")
    vumc_email_col = cols.get("vumc id email")
    tla_email_col = cols.get("tla email")

    if not (name_col and vumc_email_col and tla_email_col):
        raise RuntimeError(
            "Input file is missing one or more required columns: "
            "'Name (VUMC ID)', 'VUMC ID Email', 'TLA Email'"
        )

    enrichment_map: Dict[str, Dict[str, str]] = {}

    def add_identifier(identifier: str, enrich: Dict[str, str]):
        key = norm(identifier)
        if key and key not in enrichment_map:
            enrichment_map[key] = enrich

    for _, row in df.iterrows():
        name_val = str(row.get(name_col, "") or "").strip()
        vumc_email = str(row.get(vumc_email_col, "") or "").strip()
        tla_email = str(row.get(tla_email_col, "") or "").strip()
        uname = extract_username_from_name_field(name_val)

        enrich = {
            "inputNameVumcId": name_val,
            "inputVumcIdEmail": vumc_email,
            "inputTlaEmail": tla_email,
            "inputUsernameFromParens": uname,
        }

        add_identifier(vumc_email, enrich)
        add_identifier(tla_email, enrich)
        add_identifier(uname, enrich)
        add_identifier(name_val, enrich)

    return enrichment_map


def build_enrichment_map_from_csv(csv_path: str) -> Dict[str, Dict[str, str]]:
    with open(csv_path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        headers = [h or "" for h in (reader.fieldnames or [])]
        hmap = {h.strip().lower(): h for h in headers}

        name_col = hmap.get("name (vumc id)")
        vumc_email_col = hmap.get("vumc id email")
        tla_email_col = hmap.get("tla email")

        if not (name_col and vumc_email_col and tla_email_col):
            raise RuntimeError(
                f"{os.path.basename(csv_path)} is missing one or more required columns: "
                "'Name (VUMC ID)', 'VUMC ID Email', 'TLA Email'"
            )

        enrichment_map: Dict[str, Dict[str, str]] = {}

        def add_identifier(identifier: str, enrich: Dict[str, str]):
            key = norm(identifier)
            if key and key not in enrichment_map:
                enrichment_map[key] = enrich

        for row in reader:
            name_val = (row.get(name_col) or "").strip()
            vumc_email = (row.get(vumc_email_col) or "").strip()
            tla_email = (row.get(tla_email_col) or "").strip()
            uname = extract_username_from_name_field(name_val)

            enrich = {
                "inputNameVumcId": name_val,
                "inputVumcIdEmail": vumc_email,
                "inputTlaEmail": tla_email,
                "inputUsernameFromParens": uname,
            }

            add_identifier(vumc_email, enrich)
            add_identifier(tla_email, enrich)
            add_identifier(uname, enrich)
            add_identifier(name_val, enrich)

        return enrichment_map


def build_enrichment_map(base_dir: str, input_xlsx: str, input_csv: str) -> Dict[str, Dict[str, str]]:
    """
    Non-blocking behavior:
      - Prefer XLSX if present
      - If XLSX exists but can't be read -> warn and try CSV
      - If CSV exists -> use it
      - Else -> warn and return empty map
    """
    xlsx_path = os.path.join(base_dir, input_xlsx)
    csv_path = os.path.join(base_dir, input_csv)

    if os.path.exists(xlsx_path):
        if pd is None:
            print(f"WARNING: pandas not installed; can't read {input_xlsx}. Trying CSV instead...")
        else:
            try:
                df = pd.read_excel(xlsx_path)  # requires openpyxl typically
                return build_enrichment_map_from_dataframe(df)
            except Exception as e:
                print(f"WARNING: Could not read {input_xlsx} ({e}). Trying CSV instead...")

    if os.path.exists(csv_path):
        return build_enrichment_map_from_csv(csv_path)

    print(f"WARNING: No input file found. Expected {input_xlsx} or {input_csv} in {base_dir}")
    return {}


def ini_pick_instance(ini_path: str, section: Optional[str] = None) -> Tuple[str, str, str, str]:
    """
    Returns (base_url, username, pat, chosen_section)
    """
    if not os.path.exists(ini_path):
        raise FileNotFoundError(f"INI file not found: {ini_path}")

    cfg = configparser.ConfigParser()
    cfg.read(ini_path)

    sections = [s for s in cfg.sections()]
    if not sections:
        raise ValueError(f"No sections found in {ini_path}")

    chosen = section
    if chosen:
        if chosen not in cfg.sections():
            raise ValueError(f"Section [{chosen}] not found in {ini_path}")
    else:
        print("\nAvailable instances from INI:")
        for i, s in enumerate(sections, start=1):
            print(f"{i}. {s}")
        while True:
            choice = input("Select an instance by number: ").strip()
            if not choice.isdigit():
                print("Enter a number.")
                continue
            idx = int(choice)
            if idx < 1 or idx > len(sections):
                print("Out of range.")
                continue
            chosen = sections[idx - 1]
            break

    base_url = cfg.get(chosen, "url", fallback="").strip()
    username = cfg.get(chosen, "username", fallback="").strip()
    pat = cfg.get(chosen, "pat", fallback="").strip()

    if not base_url or not username or not pat:
        raise ValueError(f"Section [{chosen}] must contain url, username, pat")

    base_url = normalize_confluence_base_url(base_url)
    return base_url, username, pat, chosen


class ConfluenceClient:
    def __init__(self, base_url: str, username: str, pat: str, use_admin_key: bool = False):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.auth = HTTPBasicAuth(username, pat)
        self.session.headers.update({"Accept": "application/json"})
        self.use_admin_key = use_admin_key

        # Header is necessary for the bypass *after* enabling Admin Key
        if use_admin_key:
            self.session.headers.update({"Atl-Confluence-With-Admin-Key": "true"})

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def get_json(self, path: str, params: Optional[dict] = None) -> Dict[str, Any]:
        url = self._url(path)
        r = self.session.get(url, params=params, timeout=REQUEST_TIMEOUT)
        if r.status_code == 429:
            retry_after = int(r.headers.get("Retry-After", "5"))
            time.sleep(retry_after)
            r = self.session.get(url, params=params, timeout=REQUEST_TIMEOUT)
        if r.status_code >= 400:
            raise RuntimeError(f"GET {url} failed: {r.status_code} {r.text}")
        return r.json()

    def post_json(self, path: str, body: Optional[dict] = None) -> Dict[str, Any]:
        url = self._url(path)
        r = self.session.post(url, json=body, timeout=REQUEST_TIMEOUT)
        if r.status_code == 429:
            retry_after = int(r.headers.get("Retry-After", "5"))
            time.sleep(retry_after)
            r = self.session.post(url, json=body, timeout=REQUEST_TIMEOUT)
        if r.status_code >= 400:
            raise RuntimeError(f"POST {url} failed: {r.status_code} {r.text}")
        if not r.text:
            return {}
        return r.json()

    def preflight(self) -> None:
        _ = self.get_json("/rest/api/space", params={"limit": 1})

    def get_current_user(self) -> Dict[str, Any]:
        return self.get_json("/rest/api/user/current")

    # ---- Admin Key (REST v2) ----
    def get_admin_key_status_v2(self) -> Dict[str, Any]:
        # base_url already ends with /wiki, so this becomes /wiki/api/v2/admin-key
        return self.get_json("/api/v2/admin-key")

    def enable_admin_key_v2(self, duration_minutes: int = 60) -> Dict[str, Any]:
        # Enables Admin Key for calling user; body optional (default duration may be 10 minutes)
        body = {"durationInMinutes": int(duration_minutes)}
        return self.post_json("/api/v2/admin-key", body=body)

    # ---- Space/page APIs (REST v1) ----
    def list_spaces_paged(self, limit: int = 200) -> List[Dict[str, Any]]:
        spaces: List[Dict[str, Any]] = []
        start = 0
        while True:
            data = self.get_json("/rest/api/space", params={"limit": limit, "start": start})
            batch = data.get("results", []) or []
            spaces.extend(batch)
            if len(batch) < limit:
                break
            start += limit
        return spaces

    def get_space_with_permissions(self, space_key: str) -> Dict[str, Any]:
        return self.get_json(f"/rest/api/space/{space_key}", params={"expand": "permissions"})

    def list_pages_in_space(self, space_key: str) -> List[Dict[str, Any]]:
        pages: List[Dict[str, Any]] = []
        start = 0
        expand = "history.createdBy,version.by"

        while True:
            data = self.get_json(
                "/rest/api/content",
                params={
                    "spaceKey": space_key,
                    "type": "page",
                    "limit": PAGE_FETCH_LIMIT,
                    "start": start,
                    "expand": expand,
                },
            )
            batch = data.get("results", []) or []
            pages.extend(batch)
            if len(batch) < PAGE_FETCH_LIMIT:
                break
            start += PAGE_FETCH_LIMIT

        return pages

    def get_page_with_restrictions(self, content_id: str) -> Dict[str, Any]:
        expand = (
            "title,history.createdBy,version.by,"
            "restrictions.read.restrictions.user,"
            "restrictions.update.restrictions.user"
        )
        return self.get_json(f"/rest/api/content/{content_id}", params={"expand": expand})


def extract_user_identity(u: Dict[str, Any]) -> Dict[str, str]:
    return {
        "accountId": str(u.get("accountId") or ""),
        "displayName": str(u.get("displayName") or u.get("publicName") or ""),
        "email": str(u.get("email") or u.get("emailAddress") or ""),
        "username": str(u.get("username") or ""),
    }


def match_user(
    user_idents: Dict[str, str],
    enrichment_map: Dict[str, Dict[str, str]]
) -> Tuple[bool, str, str, Dict[str, str]]:
    """
    Returns:
      (is_match, matched_on, matched_input_identifier, enrichment_dict)

    matched_on:
      - substring
      - input_file
      - substring+input_file
      - "" (no match)
    """
    candidates = [
        user_idents.get("email", ""),
        user_idents.get("displayName", ""),
        user_idents.get("username", ""),
        user_idents.get("accountId", ""),
    ]

    joined = " | ".join([c for c in candidates if c])
    sub_match = (TLA_SUBSTRING in norm(joined))

    matched_input_identifier = ""
    enrichment: Dict[str, str] = {}

    for c in candidates:
        if not c:
            continue
        key = norm(c)
        if key and key in enrichment_map:
            matched_input_identifier = c
            enrichment = enrichment_map[key]
            break

    in_input = bool(matched_input_identifier)
    is_match = sub_match or in_input

    matched_on = ""
    if sub_match and in_input:
        matched_on = "substring+input_file"
    elif sub_match:
        matched_on = "substring"
    elif in_input:
        matched_on = "input_file"

    return is_match, matched_on, matched_input_identifier, enrichment


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Confluence Cloud TLA user audit (space + pages).")
    p.add_argument("--ini", default=DEFAULT_INI, help="INI file path (default: jira_config.ini)")
    p.add_argument("--section", default=None, help="INI section name to use (skips interactive selection)")
    p.add_argument("--space", default=None, help="Confluence space key to scan (e.g., VISO). If omitted, prompted.")
    p.add_argument("--admin-key", action="store_true", help="Enable Admin Key via REST v2 and send bypass header")
    p.add_argument("--admin-key-duration", type=int, default=60, help="Admin Key duration in minutes (default: 60)")
    p.add_argument("--input-xlsx", default=INPUT_XLSX, help=f"Input XLSX filename in script dir (default: {INPUT_XLSX})")
    p.add_argument("--input-csv", default=INPUT_CSV, help=f"Input CSV filename in script dir (default: {INPUT_CSV})")
    return p.parse_args()


def main():
    args = parse_args()
    base = script_dir()
    ini_path = args.ini if os.path.isabs(args.ini) else os.path.join(base, args.ini)

    try:
        base_url, username, pat, chosen_section = ini_pick_instance(ini_path, args.section)
    except Exception as e:
        print(f"ERROR loading INI: {e}")
        sys.exit(1)

    print(f"\nUsing INI section: {chosen_section}")
    print(f"Resolved Confluence API base: {base_url}")
    print(f"Admin Key requested: {'YES' if args.admin_key else 'NO'}")
    if args.admin_key:
        print(f"Admin Key duration (minutes): {args.admin_key_duration}")

    space_key = (args.space or "").strip()
    if not space_key:
        space_key = input("\nEnter Confluence SPACE KEY: ").strip()
    if not space_key:
        print("ERROR: space key is required.")
        sys.exit(1)

    enrichment_map = build_enrichment_map(base, args.input_xlsx, args.input_csv)
    print(f"\nLoaded {len(enrichment_map)} unique identifier keys from input file(s).")

    client = ConfluenceClient(base_url, username, pat, use_admin_key=args.admin_key)

    # Preflight + identity
    try:
        client.preflight()
    except Exception as e:
        print(f"\nERROR: Preflight failed. Base URL likely wrong for Confluence REST.\n{e}")
        sys.exit(2)

    try:
        me = client.get_current_user()
        print("\nAPI identity check (token user):")
        print(f"  displayName: {me.get('displayName')}")
        print(f"  accountId:   {me.get('accountId')}")
        print(f"  email:       {me.get('email') or me.get('emailAddress') or '(often blank in Cloud)'}")
    except Exception as e:
        print(f"\nWARNING: Could not fetch current API user: {e}")

    # --- Enable Admin Key (required for bypass) ---
    if args.admin_key:
        try:
            enabled = client.enable_admin_key_v2(duration_minutes=args.admin_key_duration)
            print("\nAdmin Key ENABLED via API:")
            print(f"  accountId:       {enabled.get('accountId')}")
            print(f"  expirationTime:  {enabled.get('expirationTime')}")
        except Exception as e:
            print(f"\nERROR: Failed to enable Admin Key via API: {e}")
            print("This usually means the user is not eligible to use Admin Key or the feature is not available.")
            sys.exit(5)

        # Verify status (best-effort)
        try:
            status = client.get_admin_key_status_v2()
            print("\nAdmin Key status check:")
            print(f"  expirationTime:  {status.get('expirationTime')}")
        except Exception as e:
            print(f"WARNING: Could not verify Admin Key status: {e}")

        print("\nAdmin Key header enabled on requests: YES (Atl-Confluence-With-Admin-Key: true)")

    out_name = f"confluence_tla_audit_{space_key}_{now_stamp()}.csv"
    out_path = os.path.join(base, out_name)

    rows: List[Dict[str, Any]] = []

    stats = {
        "admin_key_requested": args.admin_key,
        "admin_key_duration": args.admin_key_duration if args.admin_key else 0,
        "pages_total": 0,
        "pages_restriction_ok": 0,
        "pages_restriction_error": 0,
        "space_permission_ok": 0,
        "space_permission_error": 0,
    }

    def add_row(
        source_type: str,
        page_id: str,
        page_title: str,
        user: Dict[str, str],
        matched_on: str,
        matched_input_identifier: str,
        enrichment: Dict[str, str],
        details: str = ""
    ):
        rows.append({
            "timestamp": datetime.datetime.now().isoformat(),
            "spaceKey": space_key,
            "sourceType": source_type,
            "pageId": page_id,
            "pageTitle": page_title,

            "userDisplayName": user.get("displayName", ""),
            "userEmail": user.get("email", ""),
            "userUsername": user.get("username", ""),
            "userAccountId": user.get("accountId", ""),

            "matchedOn": matched_on,
            "matchedInputIdentifier": matched_input_identifier,

            "inputNameVumcId": enrichment.get("inputNameVumcId", ""),
            "inputVumcIdEmail": enrichment.get("inputVumcIdEmail", ""),
            "inputTlaEmail": enrichment.get("inputTlaEmail", ""),
            "inputUsernameFromParens": enrichment.get("inputUsernameFromParens", ""),

            "details": details,
        })

    # Space permissions (best-effort)
    print("\nRetrieving space permissions (best-effort)...")
    try:
        space_obj = client.get_space_with_permissions(space_key)
        perms = space_obj.get("permissions", []) or []
        stats["space_permission_ok"] = 1

        for p in perms:
            op = safe_get(p, "operation", "operation") or safe_get(p, "operation", "key") or ""
            tgt = safe_get(p, "operation", "targetType") or ""
            user_results = safe_get(p, "subjects", "user", "results", default=[]) or []
            for u in user_results:
                ident = extract_user_identity(u)
                is_match, matched_on, matched_input_identifier, enrich = match_user(ident, enrichment_map)
                if is_match:
                    add_row(
                        "space_permission",
                        "",
                        "",
                        ident,
                        matched_on,
                        matched_input_identifier,
                        enrich,
                        details=f"operation={op} targetType={tgt}"
                    )
    except Exception as e:
        stats["space_permission_error"] = 1
        add_row(
            "space_permission_error",
            "",
            "",
            {"displayName": "", "email": "", "username": "", "accountId": ""},
            "",
            "",
            {},
            details=str(e)
        )
        print(f"WARNING: Could not retrieve/parse space permissions (continuing): {e}")

    # Pages
    print("\nListing pages in space...")
    try:
        pages = client.list_pages_in_space(space_key)
    except Exception as e:
        print(f"\nERROR listing pages for space '{space_key}': {e}")
        # Diagnostics: dump a sample of space list to confirm key/tenant
        try:
            spaces = client.list_spaces_paged(limit=200)
            sample_csv = os.path.join(base, f"space_keys_sample_{now_stamp()}.csv")
            with open(sample_csv, "w", encoding="utf-8", newline="") as f:
                w = csv.writer(f)
                w.writerow(["spaceKey", "spaceName"])
                for s in spaces[:300]:
                    w.writerow([s.get("key", ""), s.get("name", "")])
            print(f"Wrote diagnostic space list sample to: {sample_csv}")
        except Exception as e2:
            print(f"Also failed to list spaces for diagnostics: {e2}")
        sys.exit(3)

    stats["pages_total"] = len(pages)
    print(f"Found {len(pages)} pages. Scanning authors/modifiers + restrictions...")

    for i, p in enumerate(pages, start=1):
        cid = str(p.get("id", ""))
        title = str(p.get("title", ""))

        # Author
        created_by = safe_get(p, "history", "createdBy", default=None)
        if isinstance(created_by, dict):
            ident = extract_user_identity(created_by)
            is_match, matched_on, matched_input_identifier, enrich = match_user(ident, enrichment_map)
            if is_match:
                add_row("page_author", cid, title, ident, matched_on, matched_input_identifier, enrich)

        # Last modifier
        modified_by = safe_get(p, "version", "by", default=None)
        if isinstance(modified_by, dict):
            ident = extract_user_identity(modified_by)
            is_match, matched_on, matched_input_identifier, enrich = match_user(ident, enrichment_map)
            if is_match:
                add_row("page_modifier", cid, title, ident, matched_on, matched_input_identifier, enrich)

        # Restrictions (extra call)
        try:
            full = client.get_page_with_restrictions(cid)
            stats["pages_restriction_ok"] += 1

            read_users = safe_get(full, "restrictions", "read", "restrictions", "user", "results", default=[]) or []
            for u in read_users:
                ident = extract_user_identity(u)
                is_match, matched_on, matched_input_identifier, enrich = match_user(ident, enrichment_map)
                if is_match:
                    add_row("page_restriction_read", cid, title, ident, matched_on, matched_input_identifier, enrich)

            upd_users = safe_get(full, "restrictions", "update", "restrictions", "user", "results", default=[]) or []
            for u in upd_users:
                ident = extract_user_identity(u)
                is_match, matched_on, matched_input_identifier, enrich = match_user(ident, enrichment_map)
                if is_match:
                    add_row("page_restriction_update", cid, title, ident, matched_on, matched_input_identifier, enrich)

        except Exception as e:
            stats["pages_restriction_error"] += 1
            add_row(
                "page_restriction_error",
                cid,
                title,
                {"displayName": "", "email": "", "username": "", "accountId": ""},
                "",
                "",
                {},
                details=str(e)
            )

        if i % 50 == 0:
            print(f"  Processed {i}/{len(pages)} pages...")

    # Summary row
    add_row(
        "run_summary",
        "",
        "",
        {"displayName": "", "email": "", "username": "", "accountId": ""},
        "",
        "",
        {},
        details=(
            f"admin_key_requested={stats['admin_key_requested']}; "
            f"admin_key_duration_min={stats['admin_key_duration']}; "
            f"pages_total={stats['pages_total']}; "
            f"pages_restriction_ok={stats['pages_restriction_ok']}; "
            f"pages_restriction_error={stats['pages_restriction_error']}; "
            f"space_permission_ok={stats['space_permission_ok']}; "
            f"space_permission_error={stats['space_permission_error']}"
        )
    )

    # Write CSV
    fieldnames = [
        "timestamp", "spaceKey", "sourceType", "pageId", "pageTitle",
        "userDisplayName", "userEmail", "userUsername", "userAccountId",
        "matchedOn", "matchedInputIdentifier",
        "inputNameVumcId", "inputVumcIdEmail", "inputTlaEmail", "inputUsernameFromParens",
        "details",
    ]
    with open(out_path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)

    print(f"\nDONE. Wrote {len(rows)} rows to:\n  {out_path}")
    print("\nCoverage summary:")
    print(f"  Admin Key requested:     {'YES' if stats['admin_key_requested'] else 'NO'}")
    print(f"  Pages found in space:    {stats['pages_total']}")
    print(f"  Restrictions fetch OK:   {stats['pages_restriction_ok']}")
    print(f"  Restrictions fetch ERR:  {stats['pages_restriction_error']}")
    print(f"  Space permissions ok?:   {bool(stats['space_permission_ok'])}")
    print(f"  Space permissions err?:  {bool(stats['space_permission_error'])}")


if __name__ == "__main__":
    main()
