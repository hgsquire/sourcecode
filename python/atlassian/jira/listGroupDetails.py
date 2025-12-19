#!/usr/bin/env python3
"""
listGroupDetails.py (limit<=100 + Events inference)
"""

import base64
import configparser
import csv
import json
import os
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path

import requests
requests.packages.urllib3.disable_warnings()

DEFAULT_TIMEOUT = 30
ADMIN_PAGE_LIMIT = 100  # Atlassian Admin API caps at 100
THROTTLE_SECONDS = 0.2

CSV_FIELDS = [
    "directoryId",
    "groupId",
    "name",
    "description",
    "managedBy",
    "externalSynced",
    "userCount",
    "created_at",
    "last_modified_at",
    "updated_at",
    "source_endpoint",
]

EVENTS_BASE = "https://api.atlassian.com/admin/v1"

CREATE_ACTION_HINTS = {"group.created", "group.added", "group-create", "directory.group.created"}
MODIFY_ACTION_HINTS = {
    "group.updated","group.renamed","group.description.updated",
    "group.member-added","group.member.removed","group.role-assigned","group.role-removed",
    "directory.group.updated","directory.group.member.added","directory.group.member.removed"
}

def _to_iso(dt_str: str) -> str:
    try:
        return datetime.fromisoformat(dt_str.replace("Z","+00:00")).astimezone(timezone.utc).isoformat()
    except Exception:
        return dt_str

def fetch_group_event_dates(org_id: str, api_key: str, group_id: str, group_name: str, days_back: int = 1825):
    headers = {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}
    created_at = None
    last_modified_at = None
    since = (datetime.now(timezone.utc) - timedelta(days=days_back)).isoformat()

    def scan(q_value: str):
        nonlocal created_at, last_modified_at
        cursor = None
        pages = 0
        while pages < 8:
            params = {"from": since, "limit": "100"}
            if q_value:
                params["q"] = q_value
            if cursor:
                params["cursor"] = cursor
            r = requests.get(f"{EVENTS_BASE}/orgs/{org_id}/events", headers=headers, params=params, timeout=30, verify=False)
            if r.status_code != 200:
                break
            data = r.json() or {}
            for ev in data.get("data", []):
                attrs = ev.get("attributes", {}) or {}
                t = _to_iso(attrs.get("time",""))
                action = attrs.get("action","")
                if action in CREATE_ACTION_HINTS and t:
                    if not created_at or t < created_at:
                        created_at = t
                if action in MODIFY_ACTION_HINTS and t:
                    if not last_modified_at or t > last_modified_at:
                        last_modified_at = t
            cursor = (data.get("links") or {}).get("next")
            pages += 1
            if not cursor:
                break

    if group_id:
        scan(group_id)
    if (created_at is None and last_modified_at is None) and group_name:
        scan(group_name)

    return created_at or "", last_modified_at or ""

def load_config(path="jira_config.ini"):
    cfg = configparser.ConfigParser()
    if not os.path.exists(path):
        print(f"Config file not found at {path}")
        sys.exit(1)
    cfg.read(path, encoding="utf-8")
    return cfg

def select_instance(cfg: configparser.ConfigParser) -> str:
    instances = [s for s in cfg.sections() if s != "Atlassian_Admin"]
    if not instances:
        print("No Jira instances found in config.")
        sys.exit(1)
    print("Available Jira Cloud instances:")
    for i, name in enumerate(instances, 1):
        print(f"{i}. {name}")
    sel = input("Select an instance by number: ").strip()
    try:
        idx = int(sel) - 1
        assert 0 <= idx < len(instances)
    except Exception:
        print("Invalid selection.")
        sys.exit(1)
    return instances[idx]

def load_instance(cfg, section):
    base_url = cfg.get(section, "url", fallback="").rstrip("/")
    username = cfg.get(section, "username", fallback="")
    pat = cfg.get(section, "pat", fallback="")
    if not base_url or not username or not pat:
        print(f"Missing url/username/pat in [{section}]")
        sys.exit(1)
    return base_url, username, pat

def load_admin(cfg):
    if not cfg.has_section("Atlassian_Admin"):
        print("Warning: [Atlassian_Admin] not found; admin API features disabled.")
        return None, None
    org_id = cfg.get("Atlassian_Admin", "org_id", fallback=None)
    api_key = cfg.get("Atlassian_Admin", "api_key", fallback=None)
    if not org_id or not api_key:
        print("Warning: org_id or api_key missing in [Atlassian_Admin]; admin API features disabled.")
        return None, None
    return org_id, api_key

def basic_auth(username, token):
    s = f"{username}:{token}".encode("utf-8")
    return base64.b64encode(s).decode("utf-8")

def jira_headers(username, token):
    return {"Authorization": f"Basic {basic_auth(username, token)}", "Accept": "application/json"}

def admin_headers(api_key):
    return {"Authorization": f"Bearer {api_key}", "Accept": "application/json", "Content-Type": "application/json"}

def _get(url, headers=None, params=None):
    resp = requests.get(url, headers=headers, params=params, timeout=DEFAULT_TIMEOUT, verify=False)
    if resp.status_code == 400 and "limit" in (resp.text or "").lower():
        # auto-clamp
        if params and "limit" in params and int(params.get("limit", 100)) > 100:
            params["limit"] = 100
            return requests.get(url, headers=headers, params=params, timeout=DEFAULT_TIMEOUT, verify=False)
    return resp

def _post(url, headers=None, json_body=None):
    resp = requests.post(url, headers=headers, json=json_body, timeout=DEFAULT_TIMEOUT, verify=False)
    if resp.status_code == 400 and "limit" in (resp.text or "").lower():
        if isinstance(json_body, dict) and "limit" in json_body and int(json_body.get("limit", 100)) > 100:
            json_body["limit"] = 100
            return requests.post(url, headers=headers, json=json_body, timeout=DEFAULT_TIMEOUT, verify=False)
    return resp

def dump_debug(dir_path, stem, payload):
    os.makedirs(dir_path, exist_ok=True)
    p = os.path.join(dir_path, f"{stem}.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

def admin_get_directories(org_id, api_key, limit=ADMIN_PAGE_LIMIT):
    limit = min(int(limit or 100), 100)
    headers = admin_headers(api_key)
    url = f"https://api.atlassian.com/admin/v2/orgs/{org_id}/directories"
    cursor = None
    while True:
        params = {"limit": limit}
        if cursor:
            params["cursor"] = cursor
        r = _get(url, headers=headers, params=params)
        if r.status_code != 200:
            raise RuntimeError(f"Admin list directories failed: {r.status_code} {r.text}")
        data = r.json() or {}
        rows = data.get("data", [])
        for row in rows:
            yield row
        cursor = (data.get("links") or {}).get("next")
        if not cursor:
            break
        time.sleep(THROTTLE_SECONDS)

def admin_get_groups_v2(org_id, api_key, directory_id, limit=ADMIN_PAGE_LIMIT, include_counts=True):
    limit = min(int(limit or 100), 100)
    headers = admin_headers(api_key)
    base = f"https://api.atlassian.com/admin/v2/orgs/{org_id}/directories/{directory_id}/groups"
    cursor = None
    while True:
        params = {"limit": limit}
        if include_counts:
            params["counts[users]"] = "true"
        if cursor:
            params["cursor"] = cursor
        r = _get(base, headers=headers, params=params)
        if r.status_code != 200:
            raise RuntimeError(f"Admin list groups failed (v2): {r.status_code} {r.text}")
        data = r.json() or {}
        rows = data.get("data", [])
        for row in rows:
            yield row
        cursor = (data.get("links") or {}).get("next")
        if not cursor:
            break
        time.sleep(THROTTLE_SECONDS)

def admin_search_groups_v1(org_id, api_key, limit=ADMIN_PAGE_LIMIT):
    limit = min(int(limit or 100), 100)
    headers = admin_headers(api_key)
    url = f"https://api.atlassian.com/admin/v1/orgs/{org_id}/groups/search"
    cursor = None
    while True:
        body = {"limit": limit}
        if cursor:
            body["cursor"] = cursor
        r = _post(url, headers=headers, json_body=body)
        if r.status_code != 200:
            raise RuntimeError(f"Admin search groups failed (v1): {r.status_code} {r.text}")
        data = r.json() or {}
        rows = data.get("data", [])
        for row in rows:
            yield row
        cursor = (data.get("links") or {}).get("next")
        if not cursor:
            break
        time.sleep(THROTTLE_SECONDS)

def jira_list_groups_basic(base_url, headers):
    url = f"{base_url}/rest/api/3/groups/picker"
    r = _get(url, headers=headers, params={"maxResults": 50})
    if r.status_code != 200:
        return []
    data = r.json() or {}
    return [g.get("name") for g in data.get("groups", [])]

def write_rows_to_csv(rows, filename):
    with open(filename, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)

def main():
    cfg = load_config("jira_config.ini")
    instance = select_instance(cfg)
    base_url, username, pat = load_instance(cfg, instance)
    org_id, api_key = load_admin(cfg)

    mode = input("Mode: [test / all]: ").strip().lower() or "test"
    debug = (input("Enable DEBUG dumps? (y/N): ").strip().lower() == "y")
    name_filter = input("Filter by group name containing (blank for none): ").strip()

    newer_than = input("Only include groups last updated/created > N days ago (blank for none): ").strip()
    older_than = input("Only include groups last updated/created < N days ago (blank for none): ").strip()
    newer_than = int(newer_than) if newer_than.isdigit() else None
    older_than = int(older_than) if older_than.isdigit() else None

    debug_dir = "_debug"
    rows_out = []

    used_admin = False
    if org_id and api_key:
        try:
            directories = list(admin_get_directories(org_id, api_key))
            if debug:
                dump_debug(debug_dir, "directories", {"data": directories})

            for d in directories:
                directory_id = d.get("id") or d.get("directoryId")
                if not directory_id:
                    continue
                for g in admin_get_groups_v2(org_id, api_key, directory_id, include_counts=True):
                    name = g.get("name") or ""
                    if name_filter and name_filter.lower() not in name.lower():
                        continue
                    row = {
                        "directoryId": directory_id,
                        "groupId": g.get("id") or "",
                        "name": name,
                        "description": g.get("description") or "",
                        "managedBy": g.get("managedBy") or "",
                        "externalSynced": g.get("externalSynced"),
                        "userCount": ((g.get("counts") or {}).get("users")),
                        "created_at": "",
                        "last_modified_at": "",
                        "updated_at": "",
                        "source_endpoint": "admin_v2_directories_groups",
                    }
                    if mode != "test":
                        try:
                            c_at, lm_at = fetch_group_event_dates(org_id, api_key, row["groupId"], row["name"])
                            row["created_at"] = c_at or row["created_at"]
                            row["last_modified_at"] = lm_at or row["last_modified_at"]
                            row["updated_at"] = row["last_modified_at"] or row["updated_at"]
                        except Exception:
                            pass
                    rows_out.append(row)
            used_admin = True
        except Exception as e:
            print(f"Admin directory/group listing failed, falling back to Jira only: {e}")
    else:
        print("Admin API not configured; using Jira fallback.")

    if not used_admin:
        jheaders = jira_headers(username, pat)
        names = jira_list_groups_basic(base_url, jheaders)
        for n in names:
            if name_filter and name_filter.lower() not in n.lower():
                continue
            rows_out.append({
                "directoryId": "",
                "groupId": "",
                "name": n,
                "description": "",
                "managedBy": "",
                "externalSynced": "",
                "userCount": "",
                "created_at": "",
                "last_modified_at": "",
                "updated_at": "",
                "source_endpoint": "jira_groups_picker",
            })

    def within_bounds(r):
        chosen = r.get("last_modified_at") or r.get("created_at") or ""
        if not chosen:
            return True
        try:
            dt = datetime.fromisoformat(chosen.replace("Z", "+00:00"))
        except Exception:
            return True
        age_days = (datetime.now(timezone.utc) - dt).days
        if newer_than is not None and age_days <= newer_than:
            return False
        if older_than is not None and age_days >= older_than:
            return False
        return True

    filtered = [r for r in rows_out if within_bounds(r)]

    out_file = "jira_groups.csv"
    write_rows_to_csv(filtered, out_file)

    if debug:
        dump_debug(debug_dir, "final_rows", filtered)

    print(f"Groups processed: {len(rows_out)}; kept after filters: {len(filtered)}. Output -> {out_file}")

if __name__ == "__main__":
    main()
