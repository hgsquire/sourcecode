#!/usr/bin/env python3
"""
confluence_fix_page_width.py

Purpose:
  For one or more Confluence Cloud workspaces (spaces), iterate all pages and
  set their pages width to full-width by manipulating the
  `content-appearance-published` content property, where necessary.

  This mimics the manual fix of:
    - Edit page
    - Click "Make page full width"
    - Publish

Config:
  Uses the an INI-style auth config as your other scripts, but with a default
  of "jira_config.ini". Each instance section must contain:
      url      = https://<your-domain>.atlassian.net
      username = <your_atlassian_email>
      pat      = <your_api_token>

Usage (interactive):
  - Run the script.
  - Select an instance from the config.
  - Choose dry-run vs. live mode.
  - Provide either:
      * a comma-separated list of workspace (space) keys/names, e.g.:
          alerts,APITEST
        or
      * a path to a CSV file that has workspace identifiers in the first column.

    The script will:
      * map each identifier to a Confluence space (matching on space key first,
        then on space name).
      * list all pages in that space.
      * for each page, create/update the `content-appearance-published`
        property to "full-width" using the v2 /pages/{id}/properties API.

Notes:
  - Uses Confluence REST v1 for space & page listing (stable and simple).
  - Uses Confluence REST v2 for content properties.
  - "Workspace name" here is interpreted as either the space key or the
    display name of the space.

"""

import base64
import configparser
import csv
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests
from requests.exceptions import RequestException

requests.packages.urllib3.disable_warnings()

CONFIG_FILE = "jira_config.ini"
DEFAULT_TIMEOUT = 30
THROTTLE_SECONDS = 0.25  # address long running commands and avoid timeouts

FULL_WIDTH_KEY = "content-appearance-published"
FULL_WIDTH_VALUE = "full-width"

# Retry settings
MAX_RETRIES = 5
RETRY_BACKOFF_BASE = 2  # seconds, exponential backoff


# ---------------------------------------------------------------------------
# HTTP helpers with retry
# ---------------------------------------------------------------------------

def _request_with_retry(
    method: str,
    url: str,
    headers: Dict[str, str],
    params: Optional[Dict] = None,
    json_body: Optional[Dict] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> requests.Response:
    """
    Generic request helper with basic retry logic on connection issues and
    some HTTP errors (429, 5xx). Raises RequestException after
    exhausting retries.
    """
    last_err: Optional[Exception] = None

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = requests.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                json=json_body,
                timeout=timeout,
                verify=False,
            )

            # Retry on HTTP errors
            if resp.status_code in (429, 500, 502, 503, 504):
                wait = RETRY_BACKOFF_BASE * attempt
                print(f"  ! HTTP {resp.status_code} for {url} (attempt {attempt}/{MAX_RETRIES}), "
                      f"sleeping {wait}s then retrying...")
                time.sleep(wait)
                last_err = RequestException(f"HTTP {resp.status_code} after {attempt} attempts")
                continue

            return resp

        except RequestException as e:
            last_err = e
            if attempt < MAX_RETRIES:
                wait = RETRY_BACKOFF_BASE * attempt
                print(f"  ! Network error on {url} (attempt {attempt}/{MAX_RETRIES}): {e}")
                print(f"    Sleeping {wait}s then retrying...")
                time.sleep(wait)
            else:
                print(f"  !! Giving up on {url} after {MAX_RETRIES} attempts: {e}")

    # If retries are exhausted 
    raise last_err if last_err else RequestException(f"Unknown error for {url}")


def _get(url: str, headers: Dict[str, str], params: Optional[Dict] = None) -> requests.Response:
    return _request_with_retry("GET", url, headers=headers, params=params)


def _post(url: str, headers: Dict[str, str], json_body: Dict) -> requests.Response:
    return _request_with_retry("POST", url, headers=headers, json_body=json_body)


def _put(url: str, headers: Dict[str, str], json_body: Dict) -> requests.Response:
    return _request_with_retry("PUT", url, headers=headers, json_body=json_body)


# ---------------------------------------------------------------------------
# Config & auth helpers
# ---------------------------------------------------------------------------

def load_config(path: str = CONFIG_FILE) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    if not os.path.exists(path):
        print(f"Config file not found at {path}")
        sys.exit(1)
    cfg.read(path, encoding="utf-8")
    return cfg


def select_instance(cfg: configparser.ConfigParser) -> str:
    # Exclude any admin-only sections if present
    instances = [s for s in cfg.sections() if s.lower() != "atlassian_admin"]
    if not instances:
        print("No instances found in config.")
        sys.exit(1)

    print("Available instances:")
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


def load_instance(cfg: configparser.ConfigParser, section: str) -> Tuple[str, str, str]:
    base_url = cfg.get(section, "url", fallback="").rstrip("/")
    username = cfg.get(section, "username", fallback="")
    pat = cfg.get(section, "pat", fallback="")

    if not base_url or not username or not pat:
        print(f"Missing url/username/pat in [{section}]")
        sys.exit(1)

    return base_url, username, pat


def get_confluence_base(url: str) -> str:
    """
    Normalize to a Confluence base URL that already contains /wiki.
    Examples:
      https://foo.atlassian.net      -> https://foo.atlassian.net/wiki
      https://foo.atlassian.net/wiki -> https://foo.atlassian.net/wiki
    """
    url = url.rstrip("/")
    if url.endswith("/wiki"):
        return url
    return url + "/wiki"


def basic_auth(username: str, token: str) -> str:
    s = f"{username}:{token}".encode("utf-8")
    return base64.b64encode(s).decode("utf-8")


def confluence_headers(username: str, token: str) -> Dict[str, str]:
    return {
        "Authorization": f"Basic {basic_auth(username, token)}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


# ---------------------------------------------------------------------------
# Workspace (space) discovery & page listing
# ---------------------------------------------------------------------------

def load_all_spaces(conf_base: str, headers: Dict[str, str]) -> List[Dict]:
    """
    Load all spaces via v1 /rest/api/space for mapping keys/names -> space.
    """
    spaces: List[Dict] = []
    start = 0
    limit = 100

    while True:
        url = f"{conf_base}/rest/api/space"
        try:
            resp = _get(url, headers, params={"start": start, "limit": limit})
        except RequestException as e:
            print(f"Error loading spaces (start={start}): {e}")
            break

        if resp.status_code != 200:
            print(f"Error loading spaces: {resp.status_code} {resp.text}")
            break

        data = resp.json() or {}
        results = data.get("results", [])
        if not results:
            break

        spaces.extend(results)

        links = data.get("_links", {}) or {}
        if "next" not in links:
            break

        start += limit
        time.sleep(THROTTLE_SECONDS)

    return spaces


def index_spaces(spaces: List[Dict]) -> Tuple[Dict[str, Dict], Dict[str, Dict]]:
    """
    Build quick lookup dicts by key and by lowercased name.
    """
    by_key: Dict[str, Dict] = {}
    by_name: Dict[str, Dict] = {}

    for s in spaces:
        key = (s.get("key") or "").strip()
        name = (s.get("name") or "").strip()
        if key:
            by_key[key] = s
        if name:
            by_name[name.lower()] = s

    return by_key, by_name


def resolve_workspace_identifier(
    identifier: str,
    by_key: Dict[str, Dict],
    by_name: Dict[str, Dict],
) -> Optional[Dict]:
    """
    Interpret identifier as either a space key or a space name.
    Order of preference:
      1. Exact key match.
      2. Case-insensitive key match.
      3. Case-insensitive name match.
    """
    ident = identifier.strip()
    if not ident:
        return None

    # 1. Exact key
    if ident in by_key:
        return by_key[ident]

    # 2. Case-insensitive key
    lower_lookup = {k.lower(): v for k, v in by_key.items()}
    if ident.lower() in lower_lookup:
        return lower_lookup[ident.lower()]

    # 3. Name match
    if ident.lower() in by_name:
        return by_name[ident.lower()]

    return None


def get_all_pages_in_space(
    conf_base: str,
    headers: Dict[str, str],
    space_key: str,
    limit: int = 100,
) -> List[Dict]:
    """
    Use v1 content listing to get all pages in a space.
    """
    pages: List[Dict] = []
    start = 0

    while True:
        url = f"{conf_base}/rest/api/content"
        params = {
            "spaceKey": space_key,
            "type": "page",
            "start": start,
            "limit": limit,
        }

        try:
            resp = _get(url, headers, params=params)
        except RequestException as e:
            print(f"  !! Error loading pages for space {space_key} (start={start}): {e}")
            break

        if resp.status_code != 200:
            print(f"Error loading pages for space {space_key}: {resp.status_code} {resp.text}")
            break

        data = resp.json() or {}
        results = data.get("results", [])
        if not results:
            break

        pages.extend(results)

        links = data.get("_links", {}) or {}
        if "next" not in links:
            break

        start += limit
        time.sleep(THROTTLE_SECONDS)

    return pages


# ---------------------------------------------------------------------------
# Page width fix via v2 content properties
# ---------------------------------------------------------------------------

def get_page_properties(
    conf_base: str,
    headers: Dict[str, str],
    page_id: str,
) -> Optional[List[Dict]]:
    """
    Get all content properties for a page via v2 API.
    On network or HTTP error, logs and returns None so callers can treat it
    as a failure for that page but continue the script.
    """
    url = f"{conf_base}/api/v2/pages/{page_id}/properties"

    try:
        resp = _get(url, headers)
    except RequestException as e:
        print(f"      !! Network error while reading properties for page {page_id}: {e}")
        return None

    if resp.status_code != 200:
        print(f"      ! Failed to read properties for page {page_id}: {resp.status_code} {resp.text}")
        return None

    data = resp.json() or {}
    return data.get("results", [])


def find_page_width_property(properties: List[Dict]) -> Optional[Dict]:
    for prop in properties:
        if prop.get("key") == FULL_WIDTH_KEY:
            return prop
    return None


def ensure_page_full_width(
    conf_base: str,
    headers: Dict[str, str],
    page_id: str,
    dry_run: bool = True,
) -> Tuple[bool, str]:
    """
    Ensure the given page has its width set to FULL_WIDTH_VALUE.

    Returns (success_flag, message).
    """
    properties = get_page_properties(conf_base, headers, page_id)
    if properties is None:
        return False, "Unable to retrieve properties (network or API error)"

    prop = find_page_width_property(properties)

    # Case 1: property doesn't exist yet -> POST
    if prop is None:
        if dry_run:
            return True, "DRY-RUN: would CREATE full-width property"

        url = f"{conf_base}/api/v2/pages/{page_id}/properties"
        body = {
            "key": FULL_WIDTH_KEY,
            "value": FULL_WIDTH_VALUE,
        }
        try:
            resp = _post(url, headers, body)
        except RequestException as e:
            return False, f"Failed to create property (network error): {e}"

        if resp.status_code not in (200, 201):
            return False, f"Failed to create property: {resp.status_code} {resp.text}"
        return True, "Created full-width property"

    # Case 2: property exists
    prop_id = prop.get("id")
    version = (prop.get("version") or {})
    current_value = prop.get("value")
    current_number = int(version.get("number", 1))

    # Already full-width?
    if current_value == FULL_WIDTH_VALUE:
        return True, "Already full-width (no change)"

    if not prop_id:
        return False, "Existing property has no id; cannot update"

    if dry_run:
        return True, "DRY-RUN: would UPDATE property to full-width"

    url = f"{conf_base}/api/v2/pages/{page_id}/properties/{prop_id}"
    body = {
        "key": FULL_WIDTH_KEY,
        "value": FULL_WIDTH_VALUE,
        "version": {
            "number": current_number + 1,
            "message": "Set to full-width via automation",
        },
    }

    try:
        resp = _put(url, headers, body)
    except RequestException as e:
        return False, f"Failed to update property (network error): {e}"

    if resp.status_code not in (200, 201):
        return False, f"Failed to update property: {resp.status_code} {resp.text}"

    return True, "Updated property to full-width"


# ---------------------------------------------------------------------------
# Input helpers
# ---------------------------------------------------------------------------

def parse_workspace_input(raw: str) -> List[str]:
    """
    Interpret the user input as either:
      - Comma-separated list of identifiers, or
      - A path to a CSV file with identifiers in the first column.
    """
    raw = raw.strip()

    # File path?
    if raw.lower().endswith(".csv") and os.path.exists(raw):
        idents: List[str] = []
        with open(raw, newline="", encoding="utf-8-sig") as f:
            reader = csv.reader(f)
            for i, row in enumerate(reader):
                if not row:
                    continue
                first = row[0].strip()
                if not first:
                    continue
                # Skip header row if it looks like a header
                if i == 0 and first.lower() in ("workspace", "space", "spacekey", "key"):
                    continue
                idents.append(first)
        return idents

    # Otherwise treat as comma-separated list
    return [p.strip() for p in raw.split(",") if p.strip()]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    cfg = load_config(CONFIG_FILE)
    instance = select_instance(cfg)
    base_url, username, pat = load_instance(cfg, instance)
    conf_base = get_confluence_base(base_url)
    headers = confluence_headers(username, pat)

    print(f"\nUsing instance [{instance}] at {conf_base}")

    dry_in = input("Dry-run only (no changes)? [Y/n]: ").strip().lower()
    dry_run = (dry_in != "n")

    ws_raw = input(
        "\nEnter a comma-separated list of workspace (space) keys/names\n"
        "OR a path to a CSV file containing them in the first column:\n> "
    )
    workspace_identifiers = parse_workspace_input(ws_raw)

    if not workspace_identifiers:
        print("No workspace identifiers provided. Exiting.")
        sys.exit(0)

    print("\nLoading all spaces for mapping...")
    spaces = load_all_spaces(conf_base, headers)
    if not spaces:
        print("No spaces returned from Confluence, or error occurred.")
        sys.exit(1)

    by_key, by_name = index_spaces(spaces)
    print(f"Loaded {len(spaces)} spaces from Confluence.")

    total_pages_processed = 0
    total_pages_changed = 0
    total_pages_skipped = 0
    total_failures = 0

    for ident in workspace_identifiers:
        print(f"\n=== Workspace identifier: [{ident}] ===")
        space = resolve_workspace_identifier(ident, by_key, by_name)
        if not space:
            print(f"  ! Could not resolve to a Confluence space (key or name). Skipping.")
            continue

        space_key = space.get("key")
        space_name = space.get("name")
        print(f"  -> Resolved to space key [{space_key}] name [{space_name}]")

        pages = get_all_pages_in_space(conf_base, headers, space_key)
        print(f"  -> Found {len(pages)} pages in space [{space_key}]")

        space_pages_processed = 0
        space_pages_changed = 0
        space_pages_skipped = 0
        space_failures = 0

        for p in pages:
            page_id = p.get("id")
            title = (p.get("title") or "").strip()
            space_pages_processed += 1
            total_pages_processed += 1

            print(f"    - Page {page_id}: {title}")
            ok, msg = ensure_page_full_width(conf_base, headers, page_id, dry_run=dry_run)
            if ok:
                print(f"      -> {msg}")
                # Count any non-"no change" as "changed/would change"
                if "Created" in msg or "Updated" in msg or "would" in msg:
                    space_pages_changed += 1
                    total_pages_changed += 1
                else:
                    space_pages_skipped += 1
                    total_pages_skipped += 1
            else:
                print(f"      !! ERROR: {msg}")
                space_failures += 1
                total_failures += 1

            time.sleep(THROTTLE_SECONDS)

        print(
            f"  Summary for space [{space_key}]: "
            f"pages={space_pages_processed}, "
            f"changed={space_pages_changed}, "
            f"skipped={space_pages_skipped}, "
            f"errors={space_failures}"
        )

    print("\n=== Overall summary ===")
    print(f"Pages processed: {total_pages_processed}")
    print(f"Pages changed (or would change in dry-run): {total_pages_changed}")
    print(f"Pages skipped (already full-width or no-op): {total_pages_skipped}")
    print(f"Failures: {total_failures}")
    print(f"Dry-run mode: {dry_run}")


if __name__ == "__main__":
    main()
