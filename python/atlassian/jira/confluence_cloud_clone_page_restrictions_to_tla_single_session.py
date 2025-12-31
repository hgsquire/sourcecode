#!/usr/bin/env python3
"""
Confluence Cloud: Clone page restrictions to mapped TLA users.

Key features
- Prompts for INI environment/section if --section is omitted (recommended usage).
- Enumerates pages via /wiki/rest/api/content (NO CQL).
- Optionally enables Admin Key (Premium/Enterprise org/site admins) and sends
  Atl-Confluence-With-Admin-Key: true on REST calls so restricted pages are visible.
- Supports mapping CSV formats:
  A) source_accountId,tla_accountId
  B) source_query,tla_query (best-effort lookup)
  C) VUMC ID Email,TLA Email,pageTitle (page-scoped instructions)

Notes
- Confluence restriction APIs require accountId. If Cloud privacy blocks email lookup, provide accountIds.
- For page-scoped CSV (C), the script matches page titles case/whitespace-insensitively and emits
  TITLE_NOT_FOUND rows for any mapping titles not found in the space.

Usage (recommended)
  python script.py --ini jira_config.ini --spacekey VISO --mapping-csv mapping.csv --use-admin-key

"""

from __future__ import annotations

import argparse
import configparser
import csv
import time
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import requests
from requests.auth import HTTPBasicAuth


# ----------------- Config -----------------

@dataclass
class InstanceConfig:
    base_url: str   # https://<site>.atlassian.net OR https://<site>.atlassian.net/wiki
    username: str
    token: str
    org_id: str = ""          # Atlassian Organization ID (optional)
    admin_api_key: str = ""   # Atlassian Admin API key (Bearer) (optional)


def normalize_cloud_base_url(url: str) -> str:
    return (url or "").strip().rstrip("/")


def cloud_rest_root(base_url: str) -> str:
    # Cloud REST v1 lives under /wiki/rest/api
    if base_url.lower().endswith("/wiki"):
        return f"{base_url}/rest/api"
    return f"{base_url}/wiki/rest/api"


def normalize_title(t: str) -> str:
    """Normalize a Confluence title for matching (case/whitespace insensitive)."""
    t = (t or "").strip()
    t = re.sub(r"\s+", " ", t)
    return t.casefold()


def read_ini(ini_path: str, section: str) -> InstanceConfig:
    cfg = configparser.ConfigParser()
    cfg.read(ini_path, encoding="utf-8")

    if section not in cfg:
        raise SystemExit(f"ERROR: INI section [{section}] not found in {ini_path}")

    base_url = cfg[section].get("url", "").strip()
    username = cfg[section].get("username", "").strip()
    token = (cfg[section].get("pat", "") or cfg[section].get("token", "") or cfg[section].get("password", "")).strip()

    if not base_url or not username or not token:
        raise SystemExit("ERROR: INI section must include url, username, and pat (or token/password).")

    org_id = (cfg[section].get("org_id", "") or cfg[section].get("organization_id", "")).strip()
    admin_api_key = (cfg[section].get("admin_api_key", "") or cfg[section].get("api_key", "") or cfg[section].get("org_api_key", "")).strip().strip('"')

    return InstanceConfig(
        base_url=normalize_cloud_base_url(base_url),
        username=username,
        token=token,
        org_id=org_id,
        admin_api_key=admin_api_key,
    )


def prompt_for_section(ini_path: str) -> str:
    """Prompt the user to select an INI section when --section is not provided."""
    cfg = configparser.ConfigParser()
    cfg.read(ini_path, encoding="utf-8")

    sections = cfg.sections()
    if not sections:
        raise SystemExit("ERROR: No sections found in INI file.")

    print("\nAvailable environments from INI:")
    for idx, sec in enumerate(sections, start=1):
        print(f"{idx}. {sec}")

    while True:
        choice = input("\nSelect environment by number: ").strip()
        if choice.isdigit():
            i = int(choice)
            if 1 <= i <= len(sections):
                return sections[i - 1]
        print("Invalid selection. Please enter a valid number.")



def load_admin_creds_from_ini(ini_path: str, selected_section: str) -> Tuple[str, str]:
    """
    If the selected section doesn't include org_id/admin_api_key, try to auto-load them from a companion
    section named '<selected_section>_Atlassian_Admin' or 'VUMC_Cloud_Atlassian_Admin' style.

    Returns (org_id, admin_api_key). Empty strings if not found.
    """
    cfg = configparser.ConfigParser()
    cfg.read(ini_path, encoding="utf-8")

    candidates = []
    # Most common convention in your INI
    candidates.append(f"{selected_section}_Atlassian_Admin")
    # Also allow '<base>_Atlassian_Admin' if section already ends with _Cloud, etc.
    # (No-op if not present.)
    for cand in candidates:
        if cand in cfg:
            org_id = (cfg[cand].get("org_id", "") or cfg[cand].get("organization_id", "")).strip()
            admin_api_key = (cfg[cand].get("admin_api_key", "") or cfg[cand].get("api_key", "") or cfg[cand].get("org_api_key", "")).strip().strip('"')
            return org_id, admin_api_key

    return "", ""

def make_session(inst: InstanceConfig) -> requests.Session:
    s = requests.Session()
    s.auth = HTTPBasicAuth(inst.username, inst.token)
    # Ensure JSON responses
    s.headers.update({"Accept": "application/json"})
    return s


def get_current_user_account_id(session: requests.Session, rest_root: str) -> Optional[str]:
    try:
        r = session.get(f"{rest_root}/user/current", timeout=30)
        if r.status_code != 200:
            return None
        data = r.json()
        if isinstance(data, dict):
            return data.get("accountId")
    except Exception:
        return None
    return None


# ----------------- Admin Key (Confluence Cloud Premium/Enterprise) -----------------

def enable_admin_key_v2(session: requests.Session, base_url: str, duration_minutes: int = 60) -> Optional[dict]:
    """
    Enable admin key for the calling user (Confluence Cloud Premium/Enterprise org/site admins).
    Endpoint (v2): POST https://{site}/wiki/api/v2/admin-key
    Subsequent calls must include header: Atl-Confluence-With-Admin-Key: true
    """
    base_url = normalize_cloud_base_url(base_url)
    url = f"{base_url}/wiki/api/v2/admin-key"
    payload = {"durationInMinutes": int(duration_minutes)} if duration_minutes and int(duration_minutes) > 0 else {}
    try:
        r = session.post(url, json=payload, headers={"Content-Type": "application/json"}, timeout=60)
        if r.status_code == 200:
            return r.json()
        return {"error": f"HTTP {r.status_code}", "detail": (r.text or "")[:800]}
    except Exception as e:
        return {"error": "exception", "detail": repr(e)}


def disable_admin_key_v2(session: requests.Session, base_url: str) -> Optional[dict]:
    """Disable admin key for the calling user (best-effort)."""
    base_url = normalize_cloud_base_url(base_url)
    url = f"{base_url}/wiki/api/v2/admin-key"
    try:
        r = session.delete(url, timeout=60)
        if r.status_code in (204, 200):
            return {"status": "disabled"}
        return {"error": f"HTTP {r.status_code}", "detail": (r.text or "")[:800]}
    except Exception as e:
        return {"error": "exception", "detail": repr(e)}



# ----------------- Atlassian Admin (Organizations) API: lookup accountId by email -----------------

def org_api_list_orgs(admin_api_key: str) -> List[dict]:
    """List orgs accessible by this Admin API key."""
    url = "https://api.atlassian.com/admin/v1/orgs"
    headers = {"Authorization": f"Bearer {admin_api_key}", "Accept": "application/json"}
    r = requests.get(url, headers=headers, timeout=60)
    if r.status_code != 200:
        raise SystemExit(f"ERROR: Admin API list orgs failed HTTP {r.status_code}: {(r.text or '')[:800]}")
    data = r.json()
    # Response is usually {data:[...], links:{...}} or a list depending on rollout; handle both
    if isinstance(data, dict) and "data" in data:
        return data.get("data") or []
    if isinstance(data, list):
        return data
    return []


def org_api_prompt_for_org_id(admin_api_key: str) -> str:
    orgs = org_api_list_orgs(admin_api_key)
    if not orgs:
        raise SystemExit("ERROR: No orgs returned for this Admin API key. Check key scopes/permissions.")
    print("\nAvailable Atlassian Orgs (Admin API key):")
    for i, o in enumerate(orgs, start=1):
        oid = o.get("id") or o.get("orgId") or ""
        name = o.get("name") or o.get("displayName") or ""
        print(f"{i}. {name} ({oid})")
    while True:
        choice = input("\nSelect org by number: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(orgs):
            o = orgs[int(choice) - 1]
            return (o.get("id") or o.get("orgId") or "").strip()
        print("Invalid selection.")


def org_api_get_directories(admin_api_key: str, org_id: str) -> list[dict]:
    """
    Get directories for an org (Admin API v2).

    GET https://api.atlassian.com/admin/v2/orgs/{orgId}/directories
    """
    url = f"https://api.atlassian.com/admin/v2/orgs/{org_id}/directories"
    headers = {
        "Authorization": f"Bearer {admin_api_key}",
        "Accept": "application/json",
    }
    r = requests.get(url, headers=headers, timeout=60)
    r.raise_for_status()
    data = r.json()
    # Typical shape: {"data":[...], "links": {...}}
    if isinstance(data, dict):
        return data.get("data") or data.get("items") or []
    return []


def org_api_iter_directory_users(admin_api_key: str, org_id: str, directory_id: str, *, limit: int = 200):
    """
    Iterate users in a directory (Admin API v2).

    GET https://api.atlassian.com/admin/v2/orgs/{orgId}/directories/{directoryId}/users
    """
    headers = {
        "Authorization": f"Bearer {admin_api_key}",
        "Accept": "application/json",
    }
    cursor = None
    while True:
        params = {"limit": limit}
        if cursor:
            params["cursor"] = cursor
        url = f"https://api.atlassian.com/admin/v2/orgs/{org_id}/directories/{directory_id}/users"
        r = requests.get(url, headers=headers, params=params, timeout=90)
        r.raise_for_status()
        payload = r.json() if r.content else {}
        items = []
        if isinstance(payload, dict):
            items = payload.get("data") or payload.get("items") or []
            links = payload.get("links") or {}
            cursor = links.get("next")
        else:
            links = {}
            cursor = None

        if not isinstance(items, list):
            items = []

        for it in items:
            if isinstance(it, dict):
                yield it

        if not cursor:
            break


# cache: (org_id) -> dict[email_lower] = accountId
_ORG_EMAIL_INDEX: dict[str, dict[str, str]] = {}


def org_api_build_email_index(admin_api_key: str, org_id: str, *, verbose: bool = False) -> dict[str, str]:
    """
    Build a case-insensitive email->accountId index using Admin API v2 directories/users.

    This avoids relying on the deprecated v1 user search endpoint, and is generally
    more reliable for resolving accountIds from email addresses.
    """
    if org_id in _ORG_EMAIL_INDEX:
        return _ORG_EMAIL_INDEX[org_id]

    idx: dict[str, str] = {}

    try:
        dirs = org_api_get_directories(admin_api_key, org_id)
    except Exception as e:
        if verbose:
            print(f"         Org API directories lookup failed: {e}")
        _ORG_EMAIL_INDEX[org_id] = idx
        return idx

    if verbose:
        dir_ids = [d.get("id") for d in dirs if isinstance(d, dict)]
        print(f"         Org API directories: {len(dir_ids)} found")

    for d in dirs:
        if not isinstance(d, dict):
            continue
        directory_id = d.get("id") or d.get("directoryId")
        if not directory_id:
            continue

        if verbose:
            print(f"         Indexing directory: {directory_id}")

        try:
            for u in org_api_iter_directory_users(admin_api_key, org_id, directory_id):
                email = (u.get("email") or "").strip()
                aid = (u.get("accountId") or u.get("account_id") or "").strip()
                if email and aid:
                    idx[email.lower()] = aid
        except Exception as e:
            if verbose:
                print(f"         WARNING: Failed to index directory {directory_id}: {e}")
            continue

    _ORG_EMAIL_INDEX[org_id] = idx
    return idx


def org_api_search_account_id_by_email(admin_api_key: str, org_id: str, email: str, *, verbose: bool = False) -> Optional[str]:
    """
    Resolve accountId from email using Admin API (Org) directory listing.

    - Builds (and caches) an org-wide email->accountId map using:
      GET /admin/v2/orgs/{orgId}/directories
      GET /admin/v2/orgs/{orgId}/directories/{directoryId}/users
    """
    email = (email or "").strip()
    if not email or "@" not in email:
        return None

    idx = org_api_build_email_index(admin_api_key, org_id, verbose=verbose)
    return idx.get(email.lower())


# ----------------- CSV -----------------

def read_mapping_csv(path: str) -> List[Dict[str, str]]:
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise SystemExit("ERROR: mapping CSV has no headers.")
        rows: List[Dict[str, str]] = []
        for row in reader:
            rows.append({(k or "").strip(): (v or "").strip() for k, v in row.items()})
        return rows



def resolve_account_id_best_effort(session: requests.Session, rest_root: str, query: str, *, admin_api_key: str = "", org_id: str = "", verbose: bool = False) -> Optional[str]:
    """
    Resolve an Atlassian accountId from:
    - admin.atlassian.com user URL
    - direct accountId
    - Atlassian Admin Org API (email -> accountId), if available
    - Confluence user search (best-effort)
    """
    query = (query or "").strip()
    if not query:
        return None

    if verbose:
        print(f"[RESOLVE] query={query!r}")

    # Admin URL -> accountId
    m_url = re.search(r"/users/([^/?#]+)", query)
    if m_url:
        aid = m_url.group(1).strip()
        if aid:
            if verbose:
                print(f"         Method: admin URL -> accountId {aid}")
            return aid

    # Direct accountId
    if re.match(r"^\d+:[0-9a-fA-F-]{36}$", query):
        if verbose:
            print(f"         Method: direct accountId -> {query}")
        return query

    # Org Admin API lookup (preferred)
    if admin_api_key and org_id and "@" in query:
        if verbose:
            print(f"         Method: Atlassian Org API (email -> accountId), org_id={org_id}")
        aid = org_api_search_account_id_by_email(admin_api_key, org_id, query)
        if aid:
            if verbose:
                print(f"         Result: FOUND accountId={aid}")
            return aid
        if verbose:
            print("         Result: NOT FOUND via Org API; falling back to Confluence search")

    # Confluence user search
    if verbose:
        print("         Method: Confluence user search (best-effort)")
    url = f"{rest_root}/user/search"
    params = {"query": query, "limit": 25}
    r = session.get(url, params=params, timeout=60)
    if r.status_code != 200:
        if verbose:
            print(f"         Result: Confluence user search HTTP {r.status_code} -> NOT FOUND")
        return None

    try:
        users = r.json()
        if not isinstance(users, list):
            # some tenants wrap responses
            users = users.get("results") if isinstance(users, dict) else []
        # Try exact email match if email is visible; otherwise first match.
        ql = query.lower()
        for u in users:
            if isinstance(u, dict):
                em = (u.get("email") or "").lower()
                aid = (u.get("accountId") or "").strip()
                if em and em == ql and aid:
                    return aid
        for u in users:
            if isinstance(u, dict) and (u.get("accountId") or "").strip():
                return u.get("accountId").strip()
    except Exception:
        pass
    return None

    # If they pasted an Atlassian admin user URL, extract the accountId
    # Example: https://admin.atlassian.com/o/<orgId>/users/<accountId>
    m_url = re.search(r"/users/([^/?#]+)", query)
    if m_url:
        cand = m_url.group(1).strip()
        if cand:
            return cand

    # If it already looks like an Atlassian accountId, use it directly
    # Common format: <digits>:<uuid>
    if re.match(r"^\d+:([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$", query):
        return query

    # If an Admin API key is available, try org user search by email first (more reliable than Confluence search)
    if admin_api_key and org_id and ("@" in query):
        aid = org_api_search_account_id_by_email(admin_api_key, org_id, query)
        if aid:
            return aid

    url = f"{rest_root}/search/user"
    params = {"cql": f'user~"{query}"', "limit": 25}
    r = session.get(url, params=params, timeout=60)
    if r.status_code != 200:
        return None

    try:
        data = r.json()
        results = data.get("results", []) if isinstance(data, dict) else []
        for item in results:
            user = item.get("user") if isinstance(item, dict) else None
            if isinstance(user, dict) and user.get("accountId"):
                return user["accountId"]
    except Exception:
        return None
    return None

    url = f"{rest_root}/search/user"
    params = {"cql": f'user~"{query}"', "limit": 25}
    r = session.get(url, params=params, timeout=60)
    if r.status_code != 200:
        return None

    try:
        data = r.json()
        results = data.get("results", []) if isinstance(data, dict) else []
        for item in results:
            user = item.get("user") if isinstance(item, dict) else None
            if isinstance(user, dict) and user.get("accountId"):
                return user["accountId"]
    except Exception:
        return None
    return None


def build_mapping(rows: List[Dict[str, str]], session: requests.Session, rest_root: str) -> Dict[str, str]:
    """
    Returns: {source_accountId: tla_accountId}
    Prefers explicit accountIds; otherwise attempts best-effort lookup via /search/user.
    """
    mapping: Dict[str, str] = {}

    for r in rows:
        src = (r.get("source_accountId") or r.get("sourceAccountId") or "").strip()
        tla = (r.get("tla_accountId") or r.get("tlaAccountId") or "").strip()

        if not src:
            q = (r.get("source_query") or r.get("sourceEmail") or r.get("source_email") or r.get("VUMC ID Email") or "").strip()
            src = resolve_account_id_best_effort(session, rest_root, q, admin_api_key=inst.admin_api_key, org_id=inst.org_id, verbose=args.verbose_identity) or ""

        if not tla:
            q = (r.get("tla_query") or r.get("tlaEmail") or r.get("tla_email") or r.get("TLA Email") or "").strip()
            tla = resolve_account_id_best_effort(session, rest_root, q, admin_api_key=inst.admin_api_key, org_id=inst.org_id, verbose=args.verbose_identity) or ""

        if src and tla:
            mapping[src] = tla

    return mapping


def parse_mapping_file(path: str) -> dict:
    rows = read_mapping_csv(path)
    cols = set(k for r in rows for k in r.keys())

    if {"VUMC ID Email", "TLA Email", "pageTitle"}.issubset(cols):
        return {"type": "page_scoped", "rows": rows}

    return {"type": "global", "rows": rows}


# ----------------- Space -> pages (NO CQL) -----------------

def iter_space_pages(session: requests.Session, rest_root: str, space_key: str, sleep_ms: int = 100):
    """Yield pages in a space using /content (no CQL)."""
    start = 0
    limit = 50

    while True:
        url = f"{rest_root}/content"
        params = {
            "spaceKey": space_key,
            "type": "page",
            "status": "current",
            "start": start,
            "limit": limit,
        }

        r = session.get(url, params=params, timeout=90)
        if r.status_code >= 400:
            try:
                err = r.json()
            except Exception:
                err = r.text
            raise SystemExit(f"ERROR: /content listing failed HTTP {r.status_code}. params={params}. Response={err}")

        data = r.json()
        results = data.get("results", []) or []
        if not results:
            return

        for p in results:
            yield p

        size = data.get("size")
        if isinstance(size, int) and size > 0:
            start += size
        else:
            start += limit

        total = data.get("totalSize")
        if isinstance(total, int) and start >= total:
            return

        time.sleep(max(0, sleep_ms) / 1000.0)


# ----------------- Restrictions -----------------

def get_restriction_users_for_operation(
    session: requests.Session,
    rest_root: str,
    content_id: str,
    op_key: str,
    sleep_ms: int = 50,
) -> List[str]:
    users: List[str] = []
    start = 0
    limit = 200

    while True:
        url = f"{rest_root}/content/{content_id}/restriction/byOperation/{op_key}"
        params = {"expand": ["user"], "start": start, "limit": limit}
        r = session.get(url, params=params, timeout=60)
        if r.status_code == 404:
            return users
        if r.status_code >= 400:
            # For permissions issues, just treat as no users
            return users

        data = r.json() if r.content else {}
        restr = (data.get("restrictions") or {})
        user_obj = (restr.get("user") or {})
        user_results = user_obj.get("results") or []

        if isinstance(user_results, list):
            for u in user_results:
                if isinstance(u, dict) and u.get("accountId"):
                    users.append(u["accountId"])

        size = user_obj.get("size")
        total = user_obj.get("totalSize")

        if isinstance(total, int) and isinstance(size, int):
            start += size
            if start >= total:
                break
        else:
            if len(user_results) < limit:
                break
            start += limit

        time.sleep(max(0, sleep_ms) / 1000.0)

    # de-dupe preserving order
    seen = set()
    deduped = []
    for a in users:
        if a not in seen:
            seen.add(a)
            deduped.append(a)
    return deduped


def add_user_to_restriction(
    session: requests.Session,
    rest_root: str,
    content_id: str,
    op_key: str,
    account_id: str,
    dry_run: bool,
) -> Tuple[bool, str]:
    url = f"{rest_root}/content/{content_id}/restriction/byOperation/{op_key}/user"
    params = {"accountId": account_id}

    if dry_run:
        return True, f"DRY-RUN: would PUT {url}?accountId={account_id}"

    r = session.put(url, params=params, timeout=60)
    if r.status_code == 200:
        return True, "OK"
    return False, f"HTTP {r.status_code}: {(r.text or '').strip()[:800]}"


# ----------------- Main -----------------

def main() -> int:
    ap = argparse.ArgumentParser(description="Clone Confluence Cloud page restrictions to mapped TLA users.")
    ap.add_argument("--ini", required=True, help="Path to INI file (e.g., jira_config.ini)")
    ap.add_argument("--section", required=False, help="INI section name (if omitted, you will be prompted)")
    ap.add_argument("--spacekey", required=True, help="Space key (e.g., VISO)")
    ap.add_argument("--mapping-csv", required=True, help="CSV mapping file (supports multiple formats)")
    ap.add_argument("--dry-run", action="store_true", help="No changes; report what would happen.")
    ap.add_argument("--sleep-ms", type=int, default=150, help="Delay between API calls (ms)")
    ap.add_argument("--out", default="page_restriction_tla_report.csv", help="Output report CSV")
    ap.add_argument("--use-admin-key", action="store_true",
                    help="Enable Confluence admin key for REST API calls (Premium/Enterprise org/site admins only). "
                         "Adds header Atl-Confluence-With-Admin-Key: true.")
    ap.add_argument("--admin-key-duration", type=int, default=60,
                    help="Admin key duration in minutes when --use-admin-key is set (default: 60).")
    ap.add_argument("--disable-admin-key-on-exit", action="store_true",
                    help="Disable admin key at script end (best-effort).")
    ap.add_argument("--verbose-identity", action="store_true", help="Print identity/accountId resolution steps.")
    args = ap.parse_args()

    section = args.section or prompt_for_section(args.ini)
    inst = read_ini(args.ini, section)
    # If admin/org lookup details aren't in the selected section, try auto-loading from a companion
    # '<section>_Atlassian_Admin' section (no extra CLI arg required).
    if (not inst.admin_api_key) or (not inst.org_id):
        org_id2, key2 = load_admin_creds_from_ini(args.ini, section)
        if key2 and not inst.admin_api_key:
            inst.admin_api_key = key2
        if org_id2 and not inst.org_id:
            inst.org_id = org_id2

    # If Admin API key is provided but org_id is not, prompt to select an org
    if inst.admin_api_key and not inst.org_id:
        inst.org_id = org_api_prompt_for_org_id(inst.admin_api_key)

    if args.verbose_identity:
        print("\n[INFO] Admin identity resolution:")
        print(f"       Admin API key present: {'YES' if bool(inst.admin_api_key) else 'NO'}")
        print(f"       Org ID present: {'YES' if bool(inst.org_id) else 'NO'} ({inst.org_id})")
        if inst.admin_api_key and inst.org_id:
            print("       User resolution order:")
            print("         1) Atlassian Admin Org API (email -> accountId)")
            print("         2) Confluence user search (best-effort)")
        else:
            print("       User resolution order:")
            print("         1) Confluence user search (best-effort)")

    rest_root = cloud_rest_root(inst.base_url)
    session = make_session(inst)

    # Optional: enable admin key for REST APIs (Premium/Enterprise org/site admins only)
    if args.use_admin_key:
        info = enable_admin_key_v2(session, inst.base_url, duration_minutes=args.admin_key_duration)
        if info and isinstance(info, dict) and info.get("error"):
            print("WARNING: Could not enable admin key via REST API. Restricted pages may remain invisible to the script.")
            print(f"         Details: {info}")
        else:
            session.headers.update({"Atl-Confluence-With-Admin-Key": "true"})
            exp = info.get("expirationTime") if isinstance(info, dict) else None
            print(f"Admin key enabled for REST API calls. Expiration: {exp}")

    # Sanity-check auth (best-effort)
    account_id = get_current_user_account_id(session, rest_root)
    if not account_id:
        print("WARNING: Session auth could not be validated via /user/current. Continuing anyway...")

    mapping_info = parse_mapping_file(args.mapping_csv)

    mapping: Dict[str, str] = {}
    # page_scoped: {normalized_title: {"title": original_title, "rows": [(vumc_email, tla_email), ...]}}
    page_scoped: Dict[str, Dict[str, object]] = {}

    if mapping_info["type"] == "global":
        mapping = build_mapping(mapping_info["rows"], session, rest_root)
    else:
        for r in mapping_info["rows"]:
            title = (r.get("pageTitle") or "").strip()
            title_norm = normalize_title(title)
            tla_email = (r.get("TLA AccountId") or r.get("tla_accountId") or r.get("TLA Email") or "").strip()
            vumc_email = (r.get("VUMC ID Email") or "").strip()
            if not title_norm or not tla_email:
                continue
            page_scoped.setdefault(title_norm, {"title": title, "rows": []})["rows"].append((vumc_email, tla_email))

    if not mapping and not page_scoped:
        print("WARNING: No user mappings were built from the mapping CSV.")
        print("         Expected accountId columns (source_accountId,tla_accountId) OR query/email columns.")
        print("         If your CSV is the 3-column report (VUMC ID Email, TLA Email, pageTitle), it will only work if user search can resolve those emails to accountIds.")

    ops = ["read", "update"]
    report_rows: List[Dict[str, str]] = []
    matched_titles = set()

    for page in iter_space_pages(session, rest_root, args.spacekey, sleep_ms=args.sleep_ms):
        page_id = str(page.get("id", ""))
        title = str(page.get("title", ""))
        if not page_id:
            continue

        title_norm = normalize_title(title)

        # If using page-scoped mapping, only process pages explicitly listed
        if page_scoped and title_norm not in page_scoped:
            continue

        for op_key in ops:
            restricted_users = get_restriction_users_for_operation(
                session, rest_root, page_id, op_key, sleep_ms=max(50, args.sleep_ms // 3)
            )

            if page_scoped:
                matched_titles.add(title_norm)
                for (vumc_email, tla_email) in page_scoped.get(title_norm, {}).get("rows", []):
                    tla_account = resolve_account_id_best_effort(session, rest_root, tla_email, admin_api_key=inst.admin_api_key, org_id=inst.org_id, verbose=args.verbose_identity)
                    if not tla_account:
                        report_rows.append({
                            "pageId": page_id,
                            "title": title,
                            "operation": op_key,
                            "source_accountId": "",
                            "tla_accountId": "",
                            "action": "TLA_LOOKUP_FAILED",
                            "status": "SKIP",
                            "detail": f"Could not resolve TLA accountId from email/query. If email lookups are blocked, provide an Atlassian Admin API key + org_id in the INI so the script can resolve accountIds via the Organizations API: {tla_email!r}. (Cloud privacy may block lookups.)",
                        })
                        continue

                    if tla_account in restricted_users:
                        report_rows.append({
                            "pageId": page_id,
                            "title": title,
                            "operation": op_key,
                            "source_accountId": "",
                            "tla_accountId": tla_account,
                            "action": "ALREADY_PRESENT",
                            "status": "OK",
                            "detail": f"TLA already present. (Row VUMC={vumc_email})",
                        })
                        continue

                    if not restricted_users:
                        report_rows.append({
                            "pageId": page_id,
                            "title": title,
                            "operation": op_key,
                            "source_accountId": "",
                            "tla_accountId": tla_account,
                            "action": "NO_EXISTING_RESTRICTION",
                            "status": "SKIP",
                            "detail": f"No existing restriction users for {op_key}; not adding TLA. (Row VUMC={vumc_email})",
                        })
                        continue

                    ok, msg = add_user_to_restriction(session, rest_root, page_id, op_key, tla_account, dry_run=args.dry_run)
                    report_rows.append({
                        "pageId": page_id,
                        "title": title,
                        "operation": op_key,
                        "source_accountId": "",
                        "tla_accountId": tla_account,
                        "action": "ADD_TLA",
                        "status": "OK" if ok else "FAIL",
                        "detail": f"{msg} (Row VUMC={vumc_email}, TLA={tla_email})",
                    })
            else:
                if not restricted_users:
                    continue

                for src_account in restricted_users:
                    tla_account = mapping.get(src_account)
                    if not tla_account:
                        report_rows.append({
                            "pageId": page_id,
                            "title": title,
                            "operation": op_key,
                            "source_accountId": src_account,
                            "tla_accountId": "",
                            "action": "NO_MAPPING",
                            "status": "SKIP",
                            "detail": "Source user is restricted on page, but no mapping found in CSV.",
                        })
                        continue

                    if tla_account in restricted_users:
                        report_rows.append({
                            "pageId": page_id,
                            "title": title,
                            "operation": op_key,
                            "source_accountId": src_account,
                            "tla_accountId": tla_account,
                            "action": "ALREADY_PRESENT",
                            "status": "OK",
                            "detail": "TLA user already present in restriction for this operation.",
                        })
                        continue

                    ok, msg = add_user_to_restriction(session, rest_root, page_id, op_key, tla_account, dry_run=args.dry_run)
                    report_rows.append({
                        "pageId": page_id,
                        "title": title,
                        "operation": op_key,
                        "source_accountId": src_account,
                        "tla_accountId": tla_account,
                        "action": "ADD_TLA",
                        "status": "OK" if ok else "FAIL",
                        "detail": msg,
                    })

            time.sleep(max(0, args.sleep_ms) / 1000.0)

    # If using page-scoped mapping, emit diagnostics for titles that were not found in the space
    if page_scoped:
        for tnorm, info in page_scoped.items():
            if tnorm in matched_titles:
                continue
            original_title = str(info.get("title", ""))
            report_rows.append({
                "pageId": "",
                "title": original_title,
                "operation": "",
                "source_accountId": "",
                "tla_accountId": "",
                "action": "TITLE_NOT_FOUND",
                "status": "SKIP",
                "detail": f"No current page in space {args.spacekey!r} matched this title (case/whitespace-insensitive). Page may be renamed, archived, deleted, or not a 'page' content type.",
            })

    # ----------------- Write report -----------------
    fieldnames = ["pageId", "title", "operation", "source_accountId", "tla_accountId", "action", "status", "detail"]
    with open(args.out, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in report_rows:
            w.writerow({k: r.get(k, "") for k in fieldnames})

    print(f"Done. Report written to: {args.out}")
    print(f"REST root used: {rest_root}")
    print("NOTE: Adding restrictions requires permission to edit each page being modified.")

    if args.disable_admin_key_on_exit and args.use_admin_key:
        di = disable_admin_key_v2(session, inst.base_url)
        print(f"Admin key disable requested (best-effort). Result: {di}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
