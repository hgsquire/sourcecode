#!/usr/bin/env python3
"""
listUserDetails.py — instance-scoped admin creds + instance-scoped output filenames
"""

import base64
import configparser
import csv
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, List, Optional

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

DEFAULT_TIMEOUT = 30
ADMIN_LIST_LIMIT = 100
THROTTLE_SECONDS = 0.15
MAX_RETRIES = 6
INITIAL_BACKOFF = 0.8
BACKOFF_MULTIPLIER = 1.8
ROWS_PER_FILE = 250_000
DEBUG_DIR = Path("_debug")

CSV_FIELDS = [
    "accountId","displayName","emailAddress","active","managed",
    "created","lastActive","product_access_summary","product_access","activity_note"
]

def load_config(path="jira_config.ini"):
    cfg = configparser.ConfigParser()
    if not os.path.exists(path):
        print(f"Config file not found at {path}")
        sys.exit(1)
    cfg.read(path, encoding="utf-8")
    return cfg

def select_instance(cfg: configparser.ConfigParser) -> str:
    instances = [s for s in cfg.sections() if not s.endswith("_Atlassian_Admin") and s != "Atlassian_Admin"]
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

def get_jira_creds(cfg: configparser.ConfigParser, section: str):
    url = cfg.get(section, "url", fallback=None)
    username = cfg.get(section, "username", fallback=None)
    pat = cfg.get(section, "pat", fallback=None)
    if not url or not username or not pat:
        print(f"Missing Jira credentials (url/username/pat) in [{section}]")
        sys.exit(1)
    return url.rstrip("/"), username, pat

def get_admin_creds(cfg: configparser.ConfigParser, instance: str):
    specific = f"{instance}_Atlassian_Admin"
    if cfg.has_section(specific):
        org_id = cfg.get(specific, "org_id", fallback=None)
        api_key = cfg.get(specific, "api_key", fallback=None)
        if org_id and api_key:
            return org_id, api_key, specific
        print(f"Warning: {specific} is present but missing org_id/api_key.")
    if cfg.has_section("Atlassian_Admin"):
        org_id = cfg.get("Atlassian_Admin", "org_id", fallback=None)
        api_key = cfg.get("Atlassian_Admin", "api_key", fallback=None)
        if org_id and api_key:
            return org_id, api_key, "Atlassian_Admin"
    return None, None, None

def basic_auth(username, token):
    s = f"{username}:{token}".encode("utf-8")
    return base64.b64encode(s).decode("utf-8")

def jira_headers(username, token):
    return {"Authorization": f"Basic {basic_auth(username, token)}", "Accept": "application/json"}

def admin_headers(api_key):
    return {"Authorization": f"Bearer {api_key}", "Accept": "application/json", "Content-Type": "application/json"}

def _request_with_retry(method: str, url: str, *, headers=None, params=None, json_body=None):
    attempt = 0
    backoff = INITIAL_BACKOFF
    while True:
        try:
            if method == "GET":
                resp = requests.get(url, headers=headers, params=params, timeout=DEFAULT_TIMEOUT, verify=False)
            else:
                resp = requests.post(url, headers=headers, json=json_body, timeout=DEFAULT_TIMEOUT, verify=False)
        except requests.RequestException:
            if attempt >= MAX_RETRIES:
                raise
            time.sleep(backoff); backoff *= BACKOFF_MULTIPLIER; attempt += 1
            continue
        if resp.status_code in (429, 502, 503, 504):
            if attempt >= MAX_RETRIES:
                return resp
            ra = resp.headers.get("Retry-After")
            sleep_for = float(ra) if ra and ra.isdigit() else backoff
            time.sleep(sleep_for); backoff *= BACKOFF_MULTIPLIER; attempt += 1
            continue
        if resp.status_code == 400 and "limit" in (resp.text or "").lower():
            if params and "limit" in params and int(params.get("limit", 100)) > 100:
                params = dict(params); params["limit"] = 100
                return requests.get(url, headers=headers, params=params, timeout=DEFAULT_TIMEOUT, verify=False)
            if json_body and isinstance(json_body, dict) and int(json_body.get("limit", 100)) > 100:
                json_body = dict(json_body); json_body["limit"] = 100
                return requests.post(url, headers=headers, json=json_body, timeout=DEFAULT_TIMEOUT, verify=False)
        return resp

def _get(url, headers=None, params=None):
    return _request_with_retry("GET", url, headers=headers, params=params)

def _post(url, headers=None, json_body=None):
    return _request_with_retry("POST", url, headers=headers, json_body=json_body)

def jira_get_myself(base_url, headers):
    return _get(f"{base_url}/rest/api/3/myself", headers=headers)

def jira_user_search_by_email(base_url, headers, email):
    from urllib.parse import quote
    q = quote(email)
    url = f"{base_url}/rest/api/3/user/search?query={q}&maxResults=10"
    r = _get(url, headers=headers)
    if r.status_code != 200:
        return None, r.status_code, r.text
    try:
        results = r.json() or []
    except Exception:
        return None, r.status_code, r.text
    if not results:
        return None, 200, "[]"
    for u in results:
        if (u.get("emailAddress") or "").lower() == email.lower():
            return u, 200, ""
    return results[0], 200, ""

def admin_v2_list_directories(org_id, api_key) -> Iterable[dict]:
    headers = admin_headers(api_key)
    url = f"https://api.atlassian.com/admin/v2/orgs/{org_id}/directories"
    cursor = None
    while True:
        params = {"limit": ADMIN_LIST_LIMIT}
        if cursor: params["cursor"] = cursor
        r = _get(url, headers=headers, params=params)
        if r.status_code != 200:
            raise RuntimeError(f"Admin v2 list directories failed: {r.status_code} {r.text}")
        data = r.json() or {}
        for d in (data.get("data") or []): yield d
        cursor = (data.get("links") or {}).get("next")
        if not cursor: break
        time.sleep(THROTTLE_SECONDS)

def admin_v2_list_users_in_directory(org_id, api_key, directory_id, *, debug_first_page_dump: Optional[str]=None) -> Iterable[dict]:
    headers = admin_headers(api_key)
    base = f"https://api.atlassian.com/admin/v2/orgs/{org_id}/directories/{directory_id}/users"
    cursor = None; page_ix = 0
    while True:
        params = {"limit": ADMIN_LIST_LIMIT}
        if cursor: params["cursor"] = cursor
        r = _get(base, headers=headers, params=params)
        if r.status_code != 200:
            raise RuntimeError(f"Admin v2 list users failed: {r.status_code} {r.text}")
        data = r.json() or {}
        if page_ix == 0 and debug_first_page_dump:
            _dump_debug(debug_first_page_dump, data)
        for u in (data.get("data") or []): yield u
        cursor = (data.get("links") or {}).get("next")
        if not cursor: break
        page_ix += 1; time.sleep(THROTTLE_SECONDS)

def admin_v1_list_users(org_id, api_key, *, debug_first_page_dump: Optional[str]=None) -> Iterable[dict]:
    headers = admin_headers(api_key)
    base = f"https://api.atlassian.com/admin/v1/orgs/{org_id}/users"
    cursor = None; page_ix = 0
    while True:
        params = {"limit": ADMIN_LIST_LIMIT}
        if cursor: params["cursor"] = cursor
        r = _get(base, headers=headers, params=params)
        if r.status_code != 200:
            raise RuntimeError(f"Admin v1 list users failed: {r.status_code} {r.text}")
        data = r.json() or {}
        if page_ix == 0 and debug_first_page_dump: _dump_debug(debug_first_page_dump, data)
        rows = []
        if isinstance(data, dict):
            if isinstance(data.get("data"), list): rows = data["data"]
            elif isinstance(data.get("results"), list): rows = data["results"]
            elif isinstance(data.get("users"), list): rows = data["users"]
        elif isinstance(data, list):
            rows = data
        for u in rows: yield u
        cursor = (data.get("links") or {}).get("next")
        if not cursor: break
        page_ix += 1; time.sleep(THROTTLE_SECONDS)

def admin_users_search_by_email(org_id, api_key, email):
    url = f"https://api.atlassian.com/admin/v1/orgs/{org_id}/users/search"
    body = {"emailUsernames": [email], "limit": 1}
    r = _post(url, headers=admin_headers(api_key), json_body=body)
    if r.status_code != 200: return None, r.status_code, r.text, r.text
    data = r.json() or {}; raw = data
    if isinstance(data, dict):
        if isinstance(data.get("data"), list) and data["data"]: return data["data"][0], 200, "", raw
        if isinstance(data.get("results"), list) and data["results"]: return data["results"][0], 200, "", raw
        if data.get("account_id"): return data, 200, "", raw
        return None, 200, "", raw
    if isinstance(data, list) and data: return data[0], 200, "", raw
    return None, 200, "", raw

def admin_get_directory_user(org_id, api_key, account_id):
    url = f"https://api.atlassian.com/admin/v1/orgs/{org_id}/directory/users/{account_id}"
    r = _get(url, headers=admin_headers(api_key))
    if r.status_code != 200: return None, r.status_code, r.text, r.text
    return r.json(), 200, "", r.json()

def admin_get_last_active(org_id, api_key, account_id):
    url = f"https://api.atlassian.com/admin/v1/orgs/{org_id}/directory/users/{account_id}/last-active-dates"
    r = _get(url, headers=admin_headers(api_key))
    if r.status_code != 200: return None, r.status_code, r.text, r.text
    return r.json(), 200, "", r.json()

def parse_iso8601(s: str):
    try:
        if s.endswith("Z"): s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s)
    except Exception:
        return None

def summarize_product_access(pa_list):
    if not pa_list: return "", "", "", "no product_access returned"
    pairs, latest_dt, latest_str = [], None, ""
    for p in pa_list or []:
        key = p.get("key") or p.get("product") or p.get("product_key") or ""
        last = p.get("last_active") or p.get("lastActive") or ""
        has_access = p.get("has_access")
        tag = f"{key}:{last}" if key and last else key or last
        if tag:
            tag += (":active" if has_access else ":noaccess") if has_access is not None else ""
            pairs.append(tag)
        if last:
            dt = parse_iso8601(last)
            if dt and (latest_dt is None or dt > latest_dt):
                latest_dt, latest_str = dt, last
    note = "ok" if pairs or latest_str else "no per-product last_active values"
    return ";".join(pairs), json.dumps(pa_list, ensure_ascii=False), latest_str, note

def shape_from_admin_row(admin_row: dict):
    account_id = admin_row.get("account_id") or admin_row.get("accountId") or admin_row.get("id") or ""
    email = admin_row.get("email") or admin_row.get("emailAddress") or ""
    display_name = admin_row.get("display_name") or admin_row.get("displayName") or ""
    product_access = admin_row.get("product_access") or []
    summary, pa_json, latest, note = summarize_product_access(product_access)
    active = any(bool(p.get("has_access", True)) for p in product_access) if isinstance(product_access, list) else True
    created = admin_row.get("createdAt") or admin_row.get("created_at") or ""
    last_active = admin_row.get("last_active") or admin_row.get("lastActive") or latest
    return {
        "accountId": account_id, "displayName": display_name, "emailAddress": email,
        "active": active, "managed": True, "created": created, "lastActive": last_active,
        "product_access_summary": summary, "product_access": pa_json, "activity_note": note
    }

def shape_unmanaged(jira_user: dict):
    return {
        "accountId": jira_user.get("accountId", ""),
        "displayName": jira_user.get("displayName", ""),
        "emailAddress": jira_user.get("emailAddress", ""),
        "active": jira_user.get("active", ""),
        "managed": False, "created": "", "lastActive": "N/A",
        "product_access_summary": "", "product_access": "",
        "activity_note": "unmanaged or not in org directory"
    }

def _dump_debug(name: str, payload):
    try:
        DEBUG_DIR.mkdir(parents=True, exist_ok=True)
        with open(DEBUG_DIR / f"{name}.json", "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
    except Exception:
        pass

class CsvWriter:
    def __init__(self, base_name: str, fields: List[str], rows_per_file: int = ROWS_PER_FILE):
        self.base_name = base_name
        self.fields = fields
        self.rows_per_file = rows_per_file if rows_per_file and rows_per_file > 0 else 0
        self.file_index = 1
        self.rows_in_current = 0
        self.writer = None
        self.file_obj = None
        self.current_path = None
        self._open_new_file()
    def _file_name_for_index(self, idx: int) -> str:
        return f"{self.base_name}.csv" if idx == 1 else f"{self.base_name}_{idx}.csv"
    def _open_new_file(self):
        if self.file_obj: self.file_obj.close()
        filename = self._file_name_for_index(self.file_index)
        self.current_path = Path(filename)
        self.file_obj = open(self.current_path, "w", newline="", encoding="utf-8-sig")
        self.writer = csv.DictWriter(self.file_obj, fieldnames=self.fields, extrasaction="ignore")
        self.writer.writeheader()
        self.rows_in_current = 0
    def write_row(self, row: dict):
        if self.rows_per_file and self.rows_in_current >= self.rows_per_file:
            self.file_index += 1; self._open_new_file()
        self.writer.writerow(row); self.rows_in_current += 1
    def close(self):
        if self.file_obj: self.file_obj.close(); self.file_obj = None

def passes_filters(row: dict, product_keys_filter, last_active_older_than_days, include_only_deactivated):
    if product_keys_filter:
        try:
            pa = json.loads(row.get("product_access") or "[]")
            keys_in_row = { (p.get("key") or p.get("product") or p.get("product_key") or "").lower() for p in pa if (p.get("key") or p.get("product") or p.get("product_key")) }
            if not keys_in_row.intersection(product_keys_filter):
                return False
        except Exception:
            return False
    if last_active_older_than_days is not None and last_active_older_than_days >= 0:
        la = row.get("lastActive")
        if la:
            try:
                if la.endswith("Z"): la = la[:-1] + "+00:00"
                la_dt = datetime.fromisoformat(la)
            except Exception:
                la_dt = None
            cutoff = datetime.now(timezone.utc) - timedelta(days=last_active_older_than_days)
            if la_dt is None or la_dt > cutoff: return False
    if include_only_deactivated:
        try:
            pa = json.loads(row.get("product_access") or "[]")
            if any(bool(p.get("has_access", False)) for p in pa): return False
        except Exception: pass
    return True

def run_test_mode(jira_url, jira_headers_dict, org_id, api_key, instance_name, debug=False):
    email = input("Enter user email to test: ").strip()
    out = CsvWriter(f"jira_users_test_{instance_name}", CSV_FIELDS, rows_per_file=0)

    if org_id and api_key:
        admin_user, code, _, raw_admin = admin_users_search_by_email(org_id, api_key, email)
        if debug and raw_admin: _dump_debug(f"{instance_name}_test_search_{email}", raw_admin)
        if code == 200 and admin_user:
            acct = admin_user.get("account_id") or admin_user.get("accountId") or admin_user.get("id")
            shaped = shape_from_admin_row(admin_user)
            if acct:
                dir_user, c2, _, raw_dir = admin_get_directory_user(org_id, api_key, acct)
                if debug and raw_dir: _dump_debug(f"{instance_name}_test_directory_{acct}", raw_dir)
                if c2 == 200 and dir_user:
                    shaped["created"] = dir_user.get("createdAt") or dir_user.get("created_at") or shaped.get("created", "")
                la, c3, _, raw_la = admin_get_last_active(org_id, api_key, acct)
                if debug and raw_la: _dump_debug(f"{instance_name}_test_last_active_{acct}", raw_la)
                if c3 == 200 and isinstance(la, dict):
                    data = la.get("data") or {}; pa = data.get("product_access") or []
                    summary, pa_json, latest, note = summarize_product_access(pa)
                    shaped["product_access_summary"] = summary or shaped["product_access_summary"]
                    shaped["product_access"] = pa_json or shaped["product_access"]
                    if latest and not shaped.get("lastActive"): shaped["lastActive"] = latest
                    if pa == [] and shaped["product_access_summary"] == "" and shaped["product_access"] == "": shaped["activity_note"] = "no product_access from last-active endpoint"
            out.write_row(shaped); out.close()
            print(f"Test export (managed) -> {out.current_path}"); return

    jira_user, code, detail = jira_user_search_by_email(jira_url, jira_headers_dict, email)
    if not jira_user:
        print(f"Jira could not find user for {email} (status {code}). Detail: {detail}")
        out.close(); return
    shaped = shape_unmanaged(jira_user); out.write_row(shaped); out.close()
    print(f"Test export (unmanaged) -> {out.current_path}")

def run_all_mode(jira_url, jira_headers_dict, org_id, api_key, instance_name, debug=False):
    if not org_id or not api_key:
        print(f"Org Admin API credentials required for 'all users' path for [{instance_name}]. Please fill [{instance_name}_Atlassian_Admin] or [Atlassian_Admin].")
        sys.exit(1)

    product_keys_in = input("Filter by product keys (comma-separated, blank for none): ").strip()
    product_keys_filter = set(k.strip().lower() for k in product_keys_in.split(",")) if product_keys_in else set()
    older_than = input("Only include users with lastActive older than N days (blank for none): ").strip()
    last_active_older_than_days = int(older_than) if older_than.isdigit() else None
    only_deactivated = input("Include only deactivated/no-access users? (y/N): ").strip().lower() == "y"

    out = CsvWriter(f"jira_users_{instance_name}", CSV_FIELDS, rows_per_file=ROWS_PER_FILE)

    total = kept = 0
    try:
        dirs = list(admin_v2_list_directories(org_id, api_key))
        if debug: _dump_debug(f"{instance_name}_v2_directories_firstpage", {"data": dirs[:10]})
        print(f"[{instance_name}] Directories discovered: {len(dirs)}")
        for d in dirs:
            directory_id = d.get("id") or d.get("directoryId")
            if not directory_id: continue
            first_dump = f"{instance_name}_v2_users_firstpage_dir_{directory_id}" if debug else None
            for admin_user in admin_v2_list_users_in_directory(org_id, api_key, directory_id, debug_first_page_dump=first_dump):
                total += 1
                shaped = shape_from_admin_row(admin_user)
                acct = shaped.get("accountId")

                if acct:
                    dir_user, code, _, raw_dir = admin_get_directory_user(org_id, api_key, acct)
                    if debug and raw_dir: _dump_debug(f"{instance_name}_directory_{acct}", raw_dir)
                    if code == 200 and dir_user:
                        shaped["created"] = dir_user.get("createdAt") or dir_user.get("created_at") or shaped["created"]
                    la, code2, _, raw_la = admin_get_last_active(org_id, api_key, acct)
                    if debug and raw_la: _dump_debug(f"{instance_name}_last_active_{acct}", raw_la)
                    if code2 == 200 and isinstance(la, dict):
                        data = la.get("data") or {}; pa = data.get("product_access") or []
                        summary, pa_json, latest, note = summarize_product_access(pa)
                        shaped["product_access_summary"] = summary or shaped["product_access_summary"]
                        shaped["product_access"] = pa_json or shaped["product_access"]
                        if latest:
                            existing = shaped.get("lastActive")
                            try:
                                def _dt(s):
                                    if s.endswith("Z"): s = s[:-1] + "+00:00"
                                    return datetime.fromisoformat(s)
                                shaped["lastActive"] = latest if not existing or (_dt(latest) and _dt(existing) and _dt(latest) > _dt(existing)) else existing
                            except Exception: pass
                        if pa == [] and shaped["product_access_summary"] == "" and shaped["product_access"] == "":
                            shaped["activity_note"] = "no product_access from last-active endpoint"

                if passes_filters(shaped, product_keys_filter, last_active_older_than_days, only_deactivated):
                    out.write_row(shaped); kept += 1
                if total % 200 == 0: print(f"[{instance_name}] Processed {total} users...")
                time.sleep(THROTTLE_SECONDS)

    except Exception as e:
        print(f"[{instance_name}] v2 listing failed: {e}. Trying v1 fallback...")
        try:
            first_dump = f"{instance_name}_v1_users_firstpage" if debug else None
            for admin_user in admin_v1_list_users(org_id, api_key, debug_first_page_dump=first_dump):
                total += 1
                shaped = shape_from_admin_row(admin_user)
                acct = shaped.get("accountId")

                if acct:
                    dir_user, code, _, raw_dir = admin_get_directory_user(org_id, api_key, acct)
                    if debug and raw_dir: _dump_debug(f"{instance_name}_directory_{acct}", raw_dir)
                    if code == 200 and dir_user:
                        shaped["created"] = dir_user.get("createdAt") or dir_user.get("created_at") or shaped["created"]
                    la, code2, _, raw_la = admin_get_last_active(org_id, api_key, acct)
                    if debug and raw_la: _dump_debug(f"{instance_name}_last_active_{acct}", raw_la)
                    if code2 == 200 and isinstance(la, dict):
                        data = la.get("data") or {}; pa = data.get("product_access") or []
                        summary, pa_json, latest, note = summarize_product_access(pa)
                        shaped["product_access_summary"] = summary or shaped["product_access_summary"]
                        shaped["product_access"] = pa_json or shaped["product_access"]
                        if latest:
                            existing = shaped.get("lastActive")
                            try:
                                def _dt(s):
                                    if s.endswith("Z"): s = s[:-1] + "+00:00"
                                    return datetime.fromisoformat(s)
                                shaped["lastActive"] = latest if not existing or (_dt(latest) and _dt(existing) and _dt(latest) > _dt(existing)) else existing
                            except Exception: pass
                        if pa == [] and shaped["product_access_summary"] == "" and shaped["product_access"] == "":
                            shaped["activity_note"] = "no product_access from last-active endpoint"

                if passes_filters(shaped, product_keys_filter, last_active_older_than_days, only_deactivated):
                    out.write_row(shaped); kept += 1
                if total % 200 == 0: print(f"[{instance_name}] Processed {total} users...")
                time.sleep(THROTTLE_SECONDS)
        except Exception as e2:
            print(f"[{instance_name}] v1 listing failed as well: {e2}")

    out.close()
    print(f"[{instance_name}] Users processed: {total}; kept after filters: {kept}. Output -> {out.current_path if out.current_path else f'jira_users_{instance_name}.csv'}")
    if ROWS_PER_FILE and out.file_index > 1:
        print(f"[{instance_name}] CSV split across {out.file_index} files (every {ROWS_PER_FILE} rows).")

def main():
    cfg = load_config("jira_config.ini")
    instance = select_instance(cfg)
    jira_url, username, pat = get_jira_creds(cfg, instance)
    org_id, api_key, admin_section = get_admin_creds(cfg, instance)

    if admin_section:
        print(f"Using admin credentials from [{admin_section}]")
    else:
        print(f"No admin credentials found for [{instance}]. You must add [{instance}_Atlassian_Admin] or [Atlassian_Admin].")
        sys.exit(1)

    j_headers = jira_headers(username, pat)
    r = jira_get_myself(jira_url, j_headers)
    if r.status_code != 200:
        print(f"Jira auth check failed for [{instance}]: {r.status_code} {r.text}")
        sys.exit(1)

    mode = input("Mode: [test / all]: ").strip().lower()
    if mode not in ("test", "all"):
        print("Invalid mode. Choose 'test' or 'all'."); sys.exit(1)

    debug = input("Enable DEBUG dumps to ./_debug? (y/N): ").strip().lower() == "y"

    if mode == "test":
        run_test_mode(jira_url, j_headers, org_id, api_key, instance, debug=debug)
    else:
        run_all_mode(jira_url, j_headers, org_id, api_key, instance, debug=debug)

if __name__ == "__main__":
    main()
