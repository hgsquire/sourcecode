#!/usr/bin/env python
"""
confluence_page_prefix_matcher.py

Uses jira_config.ini for environment selection/authentication.
Connects to Confluence, retrieves all pages across all spaces,
logs all pages, and finds pages with matching first 16 characters.

Outputs are placed in the SAME DIRECTORY where the script is executed.

Enhancement:
- Includes full workspace/page path for base and match pages in output.
"""

import configparser
import itertools
import os
import sys
import requests
import csv
import getpass
from requests.auth import HTTPBasicAuth
from urllib.parse import urljoin

# Set to False if using DC with self-signed certs
VERIFY_SSL = True


def load_config(config_path="jira_config.ini"):
    if not os.path.exists(config_path):
        print(f"Config file not found: {config_path}")
        sys.exit(1)

    config = configparser.ConfigParser()
    config.read(config_path)
    if not config.sections():
        print(f"No sections found in {config_path}")
        sys.exit(1)

    return config


def select_environment(config):
    sections = config.sections()
    print("Available environments from jira_config.ini:")
    for idx, section in enumerate(sections, start=1):
        print(f"{idx}. {section}")

    while True:
        choice = input("Select an environment by number: ").strip()
        if not choice.isdigit():
            print("Please enter a number.")
            continue
        idx = int(choice)
        if 1 <= idx <= len(sections):
            return sections[idx - 1]
        print("Invalid choice, try again.")


def get_auth_from_config(config, env_name):
    """
    Determine auth mode based on URL and config.

    Cloud (atlassian.net):
        - Uses Basic Auth with username + pat/password (API token).

    Data Center (non-atlassian.net):
        - If 'pat' present -> Bearer token.
        - Else -> Basic Auth with username + password.

    Returns:
        base_url, auth, headers
    """
    section = config[env_name]

    if "url" in section:
        base_url = section["url"].rstrip("/")
    elif "confluence_url" in section:
        base_url = section["confluence_url"].rstrip("/")
    else:
        print(f"Section [{env_name}] missing 'url' or 'confluence_url'.")
        sys.exit(1)

    username = section.get("username")
    pat = section.get("pat")
    password = section.get("password")

    # Detect cloud vs DC
    is_cloud = "atlassian.net" in base_url.lower()

    if is_cloud:
        # Jira/Confluence Cloud: Basic Auth with email + API token
        if not username:
            username = input(f"Username (email) for [{env_name}]: ").strip()

        token = pat or password
        if not token:
            token = getpass.getpass(
                f"API token/password for user '{username}' in [{env_name}]: "
            )

        auth = HTTPBasicAuth(username, token)
        headers = {}
        print("Auth mode: Cloud (Basic Auth with API token)")
    else:
        # Data Center: PAT -> Bearer token; else Basic with password
        if pat:
            # PAT for DC -> Bearer
            auth = None
            headers = {"Authorization": f"Bearer {pat}"}
            print("Auth mode: Data Center (Bearer token via PAT)")
        else:
            # Fallback to Basic Auth with password
            if not username:
                username = input(f"Username for [{env_name}]: ").strip()
            if not password:
                password = getpass.getpass(
                    f"Password for user '{username}' in [{env_name}]: "
                )
            auth = HTTPBasicAuth(username, password)
            headers = {}
            print("Auth mode: Data Center (Basic Auth with username/password)")

    return base_url, auth, headers


def confluence_get(base_url, auth, headers, path, params=None):
    """
    Helper to GET Confluence REST API with correct auth/headers.
    """
    url = urljoin(base_url + "/", path.lstrip("/"))
    response = requests.get(
        url,
        auth=auth,
        headers=headers,
        params=params,
        verify=VERIFY_SSL
    )
    if response.status_code != 200:
        print(f"Error GET {url}: {response.status_code} {response.text}")
        response.raise_for_status()
    return response.json()


def get_all_spaces(base_url, auth, headers):
    """
    Returns a list of dicts: { 'key': ..., 'name': ... }
    Uses /rest/api/space with pagination.
    """
    spaces = []
    path = "/rest/api/space"
    params = {"limit": 100}

    while True:
        data = confluence_get(base_url, auth, headers, path, params=params)
        results = data.get("results", [])

        for s in results:
            spaces.append({
                "key": s.get("key"),
                "name": s.get("name")
            })

        next_rel = data.get("_links", {}).get("next")
        if not next_rel:
            break

        path = next_rel
        params = None

    return spaces


def get_all_pages_for_space(base_url, auth, headers, space_key):
    """
    Returns a list of page records for a given space:
      {
        'space_key': ...,
        'id': ...,
        'title': ...,
        'ancestors': [ancestor_title_1, ancestor_title_2, ...]
      }

    Uses /rest/api/content?spaceKey=XXX&type=page&expand=ancestors with pagination.
    """
    pages = []
    path = "/rest/api/content"
    params = {
        "spaceKey": space_key,
        "type": "page",
        "limit": 100,
        "expand": "ancestors"
    }

    while True:
        data = confluence_get(base_url, auth, headers, path, params=params)
        results = data.get("results", [])

        for c in results:
            ancestors = c.get("ancestors") or []
            ancestor_titles = [
                a.get("title", "") for a in ancestors if a.get("title")
            ]

            pages.append({
                "id": c.get("id"),
                "title": c.get("title"),
                "space_key": space_key,
                "ancestors": ancestor_titles
            })

        next_rel = data.get("_links", {}).get("next")
        if not next_rel:
            break

        path = next_rel
        params = None

    return pages


def write_all_pages_log(all_pages, filename):
    """
    Writes all page info to CSV:
    space_key, space_name, page_id, page_title, page_path
    """
    fieldnames = ["space_key", "space_name", "page_id", "page_title", "page_path"]

    with open(filename, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for p in all_pages:
            writer.writerow({
                "space_key": p.get("space_key", ""),
                "space_name": p.get("space_name", ""),
                "page_id": p.get("id", ""),
                "page_title": p.get("title", ""),
                "page_path": p.get("page_path", "")
            })

    print(f"Wrote all pages log to: {filename}")


def find_prefix_matches(all_pages, prefix_len=16):
    """
    Group pages by the first `prefix_len` chars of the title,
    then produce pairwise matches.

    Each match contains:
      base_space_name, base_page_title, base_page_path,
      match_space_name, match_page_title, match_page_path
    """
    prefix_map = {}
    matches = []

    for p in all_pages:
        title = p.get("title") or ""
        if len(title) < prefix_len:
            continue

        prefix = title[:prefix_len]
        prefix_map.setdefault(prefix, []).append(p)

    for prefix, pages in prefix_map.items():
        if len(pages) < 2:
            continue

        for p1, p2 in itertools.combinations(pages, 2):
            matches.append({
                "base_space_name": p1.get("space_name", ""),
                "base_page_title": p1.get("title", ""),
                "base_page_path": p1.get("page_path", ""),
                "match_space_name": p2.get("space_name", ""),
                "match_page_title": p2.get("title", ""),
                "match_page_path": p2.get("page_path", "")
            })

    return matches


def write_prefix_matches(matches, filename):
    """
    Writes pairwise prefix matches to CSV:
      base_space_name, base_page_title, base_page_path,
      match_space_name, match_page_title, match_page_path
    """
    fieldnames = [
        "base_space_name",
        "base_page_title",
        "base_page_path",
        "match_space_name",
        "match_page_title",
        "match_page_path"
    ]

    with open(filename, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for m in matches:
            writer.writerow(m)

    print(f"Wrote prefix matches to: {filename}")


def main():
    # Output directory = current working directory
    output_dir = os.getcwd()

    # Load config and pick environment
    config = load_config("jira_config.ini")
    env_name = select_environment(config)
    print(f"Using environment: [{env_name}]")

    base_url, auth, headers = get_auth_from_config(config, env_name)
    print(f"Base URL: {base_url}")

    print("Retrieving Confluence spaces...")
    spaces = get_all_spaces(base_url, auth, headers)
    print(f"Found {len(spaces)} spaces.")

    all_pages = []
    for idx, space in enumerate(spaces, start=1):
        space_key = space["key"]
        space_name = space.get("name", space_key)
        print(f"[{idx}/{len(spaces)}] Getting pages for space '{space_name}' ({space_key})...")
        pages = get_all_pages_for_space(base_url, auth, headers, space_key)

        for p in pages:
            p["space_name"] = space_name
            ancestors = p.get("ancestors", [])
            # Build full path: Space / Ancestor1 / Ancestor2 / ... / Page Title
            parts = [space_name] + ancestors + [p.get("title", "")]
            # Filter out any empty segments
            p["page_path"] = " / ".join(filter(None, parts))

        all_pages.extend(pages)

    print(f"Total pages collected: {len(all_pages)}")

    # Write full pages log (in same dir as script)
    full_log_path = os.path.join(output_dir, "all_confluence_pages.csv")
    write_all_pages_log(all_pages, full_log_path)

    # Find and write prefix matches
    print("Finding prefix matches (first 16 characters of title)...")
    matches = find_prefix_matches(all_pages, prefix_len=16)
    print(f"Total matching pairs: {len(matches)}")

    match_log_path = os.path.join(output_dir, "page_prefix_matches.csv")
    write_prefix_matches(matches, match_log_path)

    print("Done.")


if __name__ == "__main__":
    main()
