#!/usr/bin/env python3
"""
Confluence Cloud: For each page in a space, if a "source" user is present in page restrictions (read/update),
add the mapped "tla" user to the same restriction operation.

"""

from __future__ import annotations

import argparse
import configparser
import csv
import json
import time
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


def normalize_cloud_base_url(url: str) -> str:
    return (url or "").strip().rstrip("/")


def cloud_rest_root(base_url: str) -> str:
    # Cloud REST v1 lives under /wiki/rest/api
    if base_url.lower().endswith("/wiki"):
        return f"{base_url}/rest/api"
    return f"{base_url}/wiki/rest/api"


def headers_json() -> Dict[str, str]:
    return {"Accept": "application/json", "Content-Type": "application/json"}


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

    return InstanceConfig(
        base_url=normalize_cloud_base_url(base_url),
        username=username,
        token=token,
    )


# ----------------- CSV -----------------

def read_mapping_csv(path: str) -> List[Dict[str, str]]:
    """
    Expected columns (recommended):
      source_accountId,tla_accountId

    Optional best-effort columns:
      source_query,tla_query   (name/email fragments used to search users)
    """
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise SystemExit("ERROR: mapping CSV has no headers.")
        rows = []
        for row in reader:
            rows.append({(k or "").strip(): (v or "").strip() for k, v in row.items()})
        return rows


def build_mapping(rows: List[Dict[str, str]], session: requests.Session, rest_root: str) -> Dict[str, str]:
    """
    Returns: {source_accountId: tla_accountId}
    Strongly prefers explicit accountIds in the CSV.
    If missing, attempts best-effort lookup via /search/user (CQL user~"query").
    """
    mapping: Dict[str, str] = {}

    for r in rows:
        src = (r.get("source_accountId") or r.get("sourceAccountId") or r.get("source") or r.get("accountId") or "").strip()
        tla = (r.get("tla_accountId") or r.get("tlaAccountId") or r.get("tla") or r.get("tla account") or "").strip()

        if not src:
            q = (r.get("source_query") or r.get("sourceEmail") or r.get("source_email") or "").strip()
            src = resolve_account_id_best_effort(session, rest_root, q) or ""

        if not tla:
            q = (r.get("tla_query") or r.get("tlaEmail") or r.get("tla_email") or "").strip()
            tla = resolve_account_id_best_effort(session, rest_root, q) or ""

        if not src or not tla:
            # skip bad rows; caller will see missing mappings in report when source user appears but no tla mapping
            continue

        mapping[src] = tla

    return mapping


def resolve_account_id_best_effort(session: requests.Session, rest_root: str, query: str) -> Optional[str]:
    """
    Best-effort lookup via:
      GET /wiki/rest/api/search/user?cql=user~"query"

    Note: user fields can be null due to privacy; email searches often fail.
    """
    query = (query or "").strip()
    if not query:
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


# ----------------- Space -> pages -----------------

def iter_space_pages(session: requests.Session, rest_root: str, space_key: str, sleep_ms: int = 100):
    """
    Yields pages in a space using CQL search:
      GET /wiki/rest/api/content/search?cql=space=KEY and type=page and status=current

    Many tenants effectively cap to 50 per request; we page with start += 50. 
    """
    start = 0
    limit = 50

    while True:
        cql = f'space="{space_key}" AND type=page AND status=current'
        url = f"{rest_root}/content/search"
        params = {
            "cql": cql,
            "start": start,
            "limit": limit,
        }
        r = session.get(url, params=params, timeout=90)
        r.raise_for_status()
        data = r.json()

        results = data.get("results", []) or []
        if not results:
            return

        for p in results:
            yield p

        start += limit
        time.sleep(max(0, sleep_ms) / 1000.0)


# ----------------- Restrictions -----------------

def get_restriction_users_for_operation(
    session: requests.Session,
    rest_root: str,
    content_id: str,
    op_key: str,
    sleep_ms: int = 50,
) -> List[str]:
    """
    Gets all user accountIds in the restriction for a given operation (read/update) for a content item.

    Endpoint:
      GET /wiki/rest/api/content/{id}/restriction/byOperation/{operationKey} 

    This endpoint supports pagination params start/limit; we fetch until done.
    """
    users: List[str] = []
    start = 0
    limit = 200

    while True:
        url = f"{rest_root}/content/{content_id}/restriction/byOperation/{op_key}"
        params = {"expand": ["user"], "start": start, "limit": limit}
        r = session.get(url, params=params, timeout=60)
        if r.status_code == 404:
            # either no content, no permission, or no restriction record returned
            return users
        r.raise_for_status()
        data = r.json() if r.content else {}

        # Response shape typically includes restrictions.user.results[*].accountId 
        restr = (data.get("restrictions") or {})
        user_obj = (restr.get("user") or {})
        user_results = user_obj.get("results") or []
        if isinstance(user_results, list):
            for u in user_results:
                if isinstance(u, dict) and u.get("accountId"):
                    users.append(u["accountId"])

        size = user_obj.get("size")
        total = user_obj.get("totalSize")

        # If API doesn't give totals, fall back to "less than limit" heuristic
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
    """
    Adds user to restriction:
      PUT /wiki/rest/api/content/{id}/restriction/byOperation/{operationKey}/user?accountId=... 
    Requires permission to edit the content. 
    """
    url = f"{rest_root}/content/{content_id}/restriction/byOperation/{op_key}/user"
    params = {"accountId": account_id}

    if dry_run:
        return True, f"DRY-RUN: would PUT {url}?accountId={account_id}"

    r = session.put(url, params=params, timeout=60)
    if r.status_code == 200:
        return True, "OK"
    return False, f"HTTP {r.status_code}: {(r.text or '').strip()[:500]}"


# ----------------- Main -----------------

def main() -> int:
    ap = argparse.ArgumentParser(description="Clone Confluence Cloud page restrictions from source users to mapped TLA users.")
    ap.add_argument("--ini", required=True, help="Path to INI file (e.g., jira_config.ini)")
    ap.add_argument("--section", required=True, help="INI section name (e.g., VUMC_Cloud)")
    ap.add_argument("--spacekey", required=True, help="Space key (e.g., VISO)")
    ap.add_argument("--mapping-csv", required=True, help="CSV mapping of source->tla users (prefer accountIds)")
    ap.add_argument("--dry-run", action="store_true", help="No changes; report what would happen.")
    ap.add_argument("--sleep-ms", type=int, default=150, help="Delay between API calls (ms)")
    ap.add_argument("--out", default="page_restriction_tla_report.csv", help="Output report CSV")
    args = ap.parse_args()

    inst = read_ini(args.ini, args.section)
    rest_root = cloud_rest_root(inst.base_url)

    session = requests.Session()
    session.auth = HTTPBasicAuth(inst.username, inst.token)

    mapping_rows = read_mapping_csv(args.mapping_csv)
    mapping = build_mapping(mapping_rows, session, rest_root)

    ops = ["read", "update"]  # Confluence restriction operations 
    report_rows: List[Dict[str, str]] = []

    for page in iter_space_pages(session, rest_root, args.spacekey, sleep_ms=args.sleep_ms):
        page_id = str(page.get("id", ""))
        title = str(page.get("title", ""))
        if not page_id:
            continue

        for op_key in ops:
            restricted_users = get_restriction_users_for_operation(session, rest_root, page_id, op_key, sleep_ms=max(50, args.sleep_ms // 3))
            if not restricted_users:
                continue

            # For each source user that appears on this page restriction, add mapped TLA user if needed
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

    fieldnames = ["pageId", "title", "operation", "source_accountId", "tla_accountId", "action", "status", "detail"]
    with open(args.out, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in report_rows:
            w.writerow({k: r.get(k, "") for k in fieldnames})

    print(f"Done. Report written to: {args.out}")
    print(f"REST root used: {rest_root}")
    print("NOTE: Adding restrictions requires permission to edit each page being modified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
