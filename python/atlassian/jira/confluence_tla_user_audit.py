#!/usr/bin/env python3
"""
Confluence Cloud - TLA user audit (space + pages) with enrichment map

Fix included:
- Auto-normalizes Confluence Cloud base URL to include /wiki for REST API calls.
  (If INI url is https://site.atlassian.net, it becomes https://site.atlassian.net/wiki)
  (If INI url already has /wiki, it is kept)

Other features:
- XLSX preferred; falls back to CSV if XLSX can't be read.
- Enrichment map adds input columns when a match comes from the input file.
"""

import csv
import os
import re
import sys
import time
import datetime
import configparser
from typing import Dict, Any, List, Optional, Tuple

import requests
from requests.auth import HTTPBasicAuth

# Optional dependency only needed for XLSX
try:
    import pandas as pd  # type: ignore
except Exception:
    pd = None


INI_FILE = "jira_config.ini"
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


def extract_username_from_name_field(name_field: str) -> str:
    m = re.search(r"\(([^)]+)\)\s*$", name_field or "")
    return m.group(1).strip() if m else ""


def normalize_confluence_base_url(url: str) -> str:
    """
    Confluence Cloud REST APIs are typically under:
      https://<site>.atlassian.net/wiki/rest/api/...

    Many INI configs already store /wiki; some store the site root.
    This function ensures the returned base ends with /wiki (no trailing slash).
    """
    u = (url or "").strip().rstrip("/")
    if not u:
        return u
    if u.endswith("/wiki"):
        return u
    # If it's an Atlassian Cloud site root, append /wiki
    # (Safe for Confluence Cloud; avoids 404s on /rest/api paths)
    return u + "/wiki"


def build_enrichment_map_from_dataframe(df) -> Dict[str, Dict[str, str]]:
    cols = {str(c).lower(): c for c in df.columns}

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


def build_enrichment_map(base_dir: str) -> Dict[str, Dict[str, str]]:
    xlsx_path = os.path.join(base_dir, INPUT_XLSX)
    csv_path = os.path.join(base_dir, INPUT_CSV)

    if os.path.exists(xlsx_path):
        if pd is None:
            print(f"WARNING: pandas not installed; can't read {INPUT_XLSX}. Trying CSV instead...")
        else:
            try:
                df = pd.read_excel(xlsx_path)  # requires openpyxl typically
                return build_enrichment_map_from_dataframe(df)
            except Exception as e:
                print(f"WARNING: Could not read {INPUT_XLSX} ({e}). Trying CSV instead...")

    if os.path.exists(csv_path):
        return build_enrichment_map_from_csv(csv_path)

    print(f"WARNING: No input file found. Expected {INPUT_XLSX} or {INPUT_CSV} in {base_dir}")
    return {}


def ini_pick_instance(ini_path: str) -> Tuple[str, str, str]:
    if not os.path.exists(ini_path):
        raise FileNotFoundError(f"INI file not found: {ini_path}")

    cfg = configparser.ConfigParser()
    cfg.read(ini_path)

    sections = [s for s in cfg.sections()]
    if not sections:
        raise ValueError(f"No sections found in {ini_path}")

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
        section = sections[idx - 1]
        break

    base_url = cfg.get(section, "url", fallback="").strip()
    username = cfg.get(section, "username", fallback="").strip()
    pat = cfg.get(section, "pat", fallback="").strip()

    if not base_url or not username or not pat:
        raise ValueError(f"Section [{section}] must contain url, username, pat")

    base_url = normalize_confluence_base_url(base_url)
    return base_url, username, pat


class ConfluenceClient:
    def __init__(self, base_url: str, username: str, pat: str):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.auth = HTTPBasicAuth(username, pat)
        self.session.headers.update({"Accept": "application/json"})

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

    def preflight(self) -> None:
        # A simple call that should succeed if base_url is right
        _ = self.get_json("/rest/api/space", params={"limit": 1})

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
            batch = data.get("results", [])
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


def main():
    base = script_dir()
    ini_path = os.path.join(base, "jira_config.ini")

    base_url, username, pat = ini_pick_instance(ini_path)
    print(f"\nResolved Confluence API base: {base_url}")

    space_key = input("\nEnter Confluence SPACE KEY: ").strip()
    if not space_key:
        print("ERROR: space key is required.")
        sys.exit(1)

    enrichment_map = build_enrichment_map(base)
    print(f"\nLoaded {len(enrichment_map)} unique identifier keys from input file(s).")

    client = ConfluenceClient(base_url, username, pat)

    # Preflight
    try:
        client.preflight()
    except Exception as e:
        print(f"\nERROR: Preflight failed. Base URL likely wrong for Confluence REST.\n{e}")
        sys.exit(2)

    out_name = f"confluence_tla_audit_{space_key}_{now_stamp()}.csv"
    out_path = os.path.join(base, out_name)

    rows: List[Dict[str, Any]] = []

    def add_row(source_type: str, page_id: str, page_title: str,
                user: Dict[str, str], matched_on: str,
                matched_input_identifier: str, enrichment: Dict[str, str], details: str = ""):
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
        perms = space_obj.get("permissions", [])
        for p in perms:
            op = safe_get(p, "operation", "operation") or safe_get(p, "operation", "key") or ""
            tgt = safe_get(p, "operation", "targetType") or ""
            user_results = safe_get(p, "subjects", "user", "results", default=[]) or []
            for u in user_results:
                ident = extract_user_identity(u)
                is_match, matched_on, matched_input_identifier, enrich = match_user(ident, enrichment_map)
                if is_match:
                    add_row("space_permission", "", "", ident, matched_on, matched_input_identifier, enrich,
                            details=f"operation={op} targetType={tgt}")
    except Exception as e:
        add_row("space_permission_error", "", "", {"displayName": "", "email": "", "username": "", "accountId": ""},
                "", "", {}, details=str(e))
        print(f"WARNING: Could not retrieve/parse space permissions (continuing): {e}")

    # Pages
    print("\nListing pages in space...")
    pages = client.list_pages_in_space(space_key)
    print(f"Found {len(pages)} pages. Scanning authors/modifiers + restrictions...")

    for i, p in enumerate(pages, start=1):
        cid = str(p.get("id", ""))
        title = str(p.get("title", ""))

        created_by = safe_get(p, "history", "createdBy", default=None)
        if isinstance(created_by, dict):
            ident = extract_user_identity(created_by)
            is_match, matched_on, matched_input_identifier, enrich = match_user(ident, enrichment_map)
            if is_match:
                add_row("page_author", cid, title, ident, matched_on, matched_input_identifier, enrich)

        modified_by = safe_get(p, "version", "by", default=None)
        if isinstance(modified_by, dict):
            ident = extract_user_identity(modified_by)
            is_match, matched_on, matched_input_identifier, enrich = match_user(ident, enrichment_map)
            if is_match:
                add_row("page_modifier", cid, title, ident, matched_on, matched_input_identifier, enrich)

        try:
            full = client.get_page_with_restrictions(cid)

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
            add_row("page_restriction_error", cid, title,
                    {"displayName": "", "email": "", "username": "", "accountId": ""},
                    "", "", {}, details=str(e))

        if i % 50 == 0:
            print(f"  Processed {i}/{len(pages)} pages...")

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


if __name__ == "__main__":
    main()
