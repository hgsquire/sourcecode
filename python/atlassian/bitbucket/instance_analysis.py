#!/usr/bin/env python3
"""
Bitbucket Instance Analysis & Relationship Mapper
----------------------------------------

Purpose
=======
Inspect a Bitbucket instance (Cloud or Server/Data Center) and export a
clean inventory of projects, repositories, pipelines (Cloud), variables,
branches, and the relationships between these hierarchical entities.

Outputs
=======
- JSON summary file with the full hierarchical tree
- CSVs (projects.csv, repos.csv, pipelines.csv [Cloud], variables.csv [Cloud], branches.csv)
- relationships.csv (edges for project→repo and repo→pipeline)
- Optional GraphViz .dot (and .png if graphviz is available) representing the graph

Authentication
==============
Bitbucket Cloud: supply username and App Password.
Bitbucket Server/DC: supply username and password (or Personal Access Token as the password).

Quick Examples
==============
# Bitbucket Cloud (pipelines supported):
python instance_analysis.py \
  --cloud \
  --workspace YOUR_WORKSPACE_SLUG \
  --username YOUR_USERNAME \
  --app-password YOUR_APP_PASSWORD \
  --out ./out_cloud \
  --include-pipeline-yaml \
  --graph

# Bitbucket Server/DC (no pipelines feature):
python instance_analysis.py \
  --server \
  --base-url https://bitbucket.example.com \
  --username admin \
  --password XXXXXXXXX \
  --out ./out_server \
  --verify-ssl false \
  --graph

Notes
=====
- For Cloud, "pipelines" exist. For Server/DC, the script will gather build statuses (if obtainable) and webhooks but
  will NOT find Bitbucket Pipelines because that is a Cloud-only feature.
- Pagination is fully handled.
- Rate limiting backoff is minimal (sleep), tweak as needed.

"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
import datetime as dt
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple
import configparser
from pathlib import Path

try:
    import requests
except ImportError:
    print("This script requires the 'requests' package. Install with: pip install requests", file=sys.stderr)
    sys.exit(1)

# -----------------------------
# Utility & I/O helpers
# -----------------------------

def ensure_outdir(outdir: str) -> None:
    os.makedirs(outdir, exist_ok=True)


def iso_now() -> str:
    # Use timezone-aware UTC to avoid deprecation warnings on Python 3.12+
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def write_json(path: str, data: Any) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def write_csv(path: str, header: List[str], rows: Iterable[Iterable[Any]]) -> None:
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        for r in rows:
            writer.writerow(r)


def safe_get(d: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    cur: Any = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur

# -----------------------------
# Config helpers (env + INI file; default filename: auth.ini)
# -----------------------------

def first_nonempty(*vals):
    for v in vals:
        if v is None:
            continue
        if isinstance(v, str) and v.strip() == "":
            continue
        return v
    return None


def asbool(v, default=True):
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    return s in ("1", "true", "t", "yes", "y", "on")


def config_candidates(user_path: Optional[str]) -> List[str]:
    cands: List[str] = []
    if user_path:
        cands.append(user_path)
    # project local
    cands.append(os.path.join(os.getcwd(), "auth.ini"))
    # Windows APPDATA
    appdata = os.getenv("APPDATA")
    if appdata:
        cands.append(os.path.join(appdata, "BitbucketInventory", "auth.ini"))
    # *nix ~/.config
    cands.append(os.path.join(Path.home(), ".config", "bitbucket_inventory", "auth.ini"))
    return cands


def load_config(paths: List[str]) -> Optional[configparser.ConfigParser]:
    cfg = configparser.ConfigParser()
    found = cfg.read([p for p in paths if p])
    return cfg if found else None


def cfg_get(cfg: Optional[configparser.ConfigParser], section: str, option: str) -> Optional[str]:
    if cfg and cfg.has_option(section, option):
        return cfg.get(section, option)
    return None


# -----------------------------
# Bitbucket Cloud client
# -----------------------------

class BitbucketCloudClient:
    def __init__(self, workspace: str, username: Optional[str] = None, app_password: Optional[str] = None, access_token: Optional[str] = None, rate_limit_sleep: float = 0.25):
        self.base = "https://api.bitbucket.org/2.0"
        self.workspace = workspace
        self.headers = {"Authorization": f"Bearer {access_token}"} if access_token else {}
        self.auth = None if access_token else (username, app_password)
        self.rate_limit_sleep = rate_limit_sleep

    def _get(self, url: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        time.sleep(self.rate_limit_sleep)
        r = requests.get(url, auth=self.auth, headers=self.headers, params=params, timeout=60)
        if r.status_code >= 400:
            raise RuntimeError(f"Bitbucket Cloud API error {r.status_code}: {r.text}")
        return r.json()

    def _paginate(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Iterable[Dict[str, Any]]:
        url = f"{self.base}{endpoint}"
        q = dict(params or {})
        while True:
            data = self._get(url, q)
            values = data.get("values", [])
            for item in values:
                yield item
            url = data.get("next")
            if not url:
                break

    # -------- Projects / Repos --------
    def list_projects(self) -> List[Dict[str, Any]]:
        return list(self._paginate(f"/workspaces/{self.workspace}/projects"))

    def list_repos(self, project_key: Optional[str] = None) -> List[Dict[str, Any]]:
        params = {"q": f"project.key=\"{project_key}\""} if project_key else None
        return list(self._paginate(f"/repositories/{self.workspace}", params=params))

    def get_default_branch_name(self, repo: Dict[str, Any]) -> Optional[str]:
        main_branch = repo.get("mainbranch") or {}
        return main_branch.get("name")

    # -------- Branches --------
    def list_branches(self, repo_slug: str) -> List[Dict[str, Any]]:
        return list(self._paginate(f"/repositories/{self.workspace}/{repo_slug}/refs/branches"))

    # -------- Pipelines & Variables --------
    def list_pipelines(self, repo_slug: str, max_items: Optional[int] = None) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        for p in self._paginate(f"/repositories/{self.workspace}/{repo_slug}/pipelines/"):
            items.append(p)
            if max_items and len(items) >= max_items:
                break
        return items

    def list_pipeline_steps(self, repo_slug: str, pipeline_uuid: str) -> List[Dict[str, Any]]:
        # pipeline_uuid typically includes braces; ensure it's URL safe
        uuid = pipeline_uuid
        if not uuid.startswith("{"):
            # Most APIs return with braces, but just in case
            uuid = "{" + uuid + "}"
        return list(self._paginate(f"/repositories/{self.workspace}/{repo_slug}/pipelines/{uuid}/steps"))

    def list_workspace_variables(self) -> List[Dict[str, Any]]:
        """Return workspace-level pipeline variables if accessible.
        Gracefully handle 404/403 by returning an empty list (feature not available or insufficient perms)."""
        url = f"{self.base}/workspaces/{self.workspace}/pipelines-config/variables/"
        try:
            # Probe once to get a clear status
            time.sleep(self.rate_limit_sleep)
            r = requests.get(url, auth=self.auth, headers=getattr(self, 'headers', {}), timeout=60)
            if r.status_code == 404:
                print(f"[Cloud] Workspace variables endpoint not found for workspace '{self.workspace}' (HTTP 404). Skipping.")
                return []
            if r.status_code == 403:
                print(f"[Cloud] No permission to read workspace variables (HTTP 403). Skipping.")
                return []
            if r.status_code >= 400:
                raise RuntimeError(f"Bitbucket Cloud API error {r.status_code}: {r.text}")
            # If OK, paginate for full list
            return list(self._paginate(f"/workspaces/{self.workspace}/pipelines-config/variables/"))
        except RuntimeError as e:
            # Defensive: swallow 404/403 raised from paginate path if any
            msg = str(e)
            if " 404:" in msg or " 403:" in msg:
                print(f"[Cloud] Workspace variables not accessible ({msg.strip()}). Skipping.")
                return []
            raise

    def list_repo_variables(self, repo_slug: str) -> List[Dict[str, Any]]:
        return list(self._paginate(f"/repositories/{self.workspace}/{repo_slug}/pipelines_config/variables/"))

    def get_file_from_default(self, repo_slug: str, path: str) -> Optional[str]:
        # Get repo to find main branch, then fetch file
        # Alternatively we can request the default branch via refs/default, but using mainbranch from list_repos is fine
        try:
            branches = self.list_branches(repo_slug)
            # Heuristic: prefer branch marked as default if present in branch metadata; fall back to 'main'/'master'
            default_branch = None
            for b in branches:
                if b.get("default", False):
                    default_branch = b.get("name")
                    break
            if not default_branch:
                names = [b.get("name") for b in branches]
                for candidate in ("main", "master", "develop"):
                    if candidate in names:
                        default_branch = candidate
                        break
            ref = default_branch or (branches[0]["name"] if branches else "main")
        except Exception:
            ref = "main"
        url = f"{self.base}/repositories/{self.workspace}/{repo_slug}/src/{ref}/{path}"
        time.sleep(self.rate_limit_sleep)
        r = requests.get(url, auth=self.auth, headers=self.headers, timeout=60)
        if r.status_code == 404:
            return None
        if r.status_code >= 400:
            raise RuntimeError(f"Failed fetching {path} from {repo_slug}@{ref}: {r.status_code} {r.text}")
        return r.text


# -----------------------------
# Bitbucket Server/DC client
# -----------------------------

class BitbucketServerClient:
    def __init__(self, base_url: str, username: str, password: str, verify_ssl: bool = True, rate_limit_sleep: float = 0.25):
        self.base = base_url.rstrip("/")
        self.auth = (username, password)
        self.verify_ssl = verify_ssl
        self.rate_limit_sleep = rate_limit_sleep

    def _get(self, url: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        time.sleep(self.rate_limit_sleep)
        r = requests.get(url, auth=self.auth, params=params, verify=self.verify_ssl, timeout=60)
        if r.status_code >= 400:
            raise RuntimeError(f"Bitbucket Server/DC API error {r.status_code}: {r.text}")
        return r.json()

    def _paginate(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Iterable[Dict[str, Any]]:
        url = f"{self.base}{endpoint}"
        start = 0
        more = True
        q = dict(params or {})
        q.setdefault("limit", 100)
        while more:
            q["start"] = start
            data = self._get(url, q)
            values = data.get("values", [])
            for item in values:
                yield item
            is_last_page = data.get("isLastPage", True)
            if is_last_page:
                break
            start = data.get("nextPageStart", start + len(values))

    # -------- Projects / Repos --------
    def list_projects(self) -> List[Dict[str, Any]]:
        return list(self._paginate("/rest/api/1.0/projects"))

    def list_repos(self, project_key: str) -> List[Dict[str, Any]]:
        return list(self._paginate(f"/rest/api/1.0/projects/{project_key}/repos"))

    # -------- Branches --------
    def list_branches(self, project_key: str, repo_slug: str) -> List[Dict[str, Any]]:
        return list(self._paginate(f"/rest/api/1.0/projects/{project_key}/repos/{repo_slug}/branches"))

    # -------- Webhooks (if permitted) --------
    def list_webhooks(self, project_key: str, repo_slug: str) -> List[Dict[str, Any]]:
        try:
            return list(self._paginate(f"/rest/api/1.0/projects/{project_key}/repos/{repo_slug}/webhooks"))
        except RuntimeError:
            return []  # Not accessible without admin


# -----------------------------
# Analyzer Orchestration
# -----------------------------

@dataclass
class InventoryOptions:
    include_pipeline_yaml: bool = False
    graph: bool = False
    max_pipelines_per_repo: Optional[int] = None


class InventoryRunner:
    def __init__(self, outdir: str, opts: InventoryOptions):
        self.outdir = outdir
        self.opts = opts
        ensure_outdir(self.outdir)
        self.edges: List[Tuple[str, str, str, str, str]] = []  # (parent_type, parent_id, child_type, child_id, label)

    def _preflight_cloud(self, client: BitbucketCloudClient) -> None:
        """Validate that auth works and the configured workspace is accessible.
        Provides actionable error messages for common pitfalls.
        """
        import requests
        is_bearer = bool(getattr(client, "headers", {}).get("Authorization", "").startswith("Bearer "))
        mode = "Bearer" if is_bearer else "Basic"
        print(f"[Cloud] Auth mode: {mode}")
        # Primary probe
        try:
            if is_bearer:
                r = requests.get(f"{client.base}/workspaces?role=member", headers=client.headers, timeout=60)
            else:
                r = requests.get(f"{client.base}/user", auth=client.auth, timeout=60)
        except Exception as e:
            raise RuntimeError(f"Failed to reach Bitbucket API: {e}")
        if r.status_code == 401:
            if is_bearer:
                raise RuntimeError(
                    "401 Unauthorized: Bearer token rejected. If your token starts with 'ATATT', that's an Atlassian API token (Basic only). "
                    "Use it via username=email + app_password=token, or create a Bitbucket Access Token and use --access-token."
                )
            else:
                raise RuntimeError(
                    "401 Unauthorized: Basic auth rejected. Ensure username is your Atlassian account email and the password is a Bitbucket-enabled API token."
                )
        if r.status_code >= 400:
            raise RuntimeError(f"Bitbucket API preflight failed (HTTP {r.status_code}): {r.text}")
        # Workspace visibility
        if is_bearer:
            wr = requests.get(f"{client.base}/workspaces?role=member", headers=client.headers, timeout=60)
        else:
            wr = requests.get(f"{client.base}/workspaces?role=member", auth=client.auth, timeout=60)
        if wr.status_code == 200:
            slugs = [w.get("slug") for w in wr.json().get("values", [])]
            if getattr(client, "workspace", None) and client.workspace not in slugs:
                print(f"[WARN] Workspace '{client.workspace}' not found in your memberships: {', '.join(slugs) or '(none)'}")

    # -------- Cloud path --------
    def run_cloud(self, client: BitbucketCloudClient) -> None:
        print("[Cloud] Verifying credentials…")
        self._preflight_cloud(client)
        print("[Cloud] Fetching projects…")
        projects = client.list_projects()

        print("[Cloud] Fetching repos…")
        # Build map project_key -> repos
        repos_by_project: Dict[str, List[Dict[str, Any]]] = {}
        all_repos: List[Dict[str, Any]] = []
        for proj in projects:
            pkey = proj.get("key")
            repos = client.list_repos(project_key=pkey)
            repos_by_project[pkey] = repos
            all_repos.extend(repos)
            for r in repos:
                self.edges.append(("project", pkey, "repo", r.get("slug", r.get("name", "")), "contains"))

        # Branches
        branches_rows: List[List[Any]] = []
        print("[Cloud] Fetching branches per repo…")
        for r in all_repos:
            rslug = r.get("slug") or r.get("name")
            for b in client.list_branches(rslug):
                branches_rows.append([
                    client.workspace,
                    safe_get(r, "project", "key"),
                    rslug,
                    b.get("name"),
                    b.get("target", {}).get("hash"),
                    b.get("default", False),
                    b.get("date"),
                ])

        # Pipelines (and steps/variables optionally)
        pipelines_rows: List[List[Any]] = []
        steps_rows: List[List[Any]] = []
        var_rows: List[List[Any]] = []
        yaml_rows: List[List[Any]] = []

        print("[Cloud] Fetching workspace variables…")
        for v in client.list_workspace_variables():
            var_rows.append(["workspace", client.workspace, "", v.get("uuid"), v.get("key"), v.get("secured", False), v.get("type")])

        print("[Cloud] Fetching pipelines & repo variables…")
        for r in all_repos:
            rslug = r.get("slug") or r.get("name")

            # Repo variables
            for v in client.list_repo_variables(rslug):
                var_rows.append(["repo", client.workspace, rslug, v.get("uuid"), v.get("key"), v.get("secured", False), v.get("type")])

            # Pipelines
            try:
                pipelines = client.list_pipelines(rslug, max_items=self.opts.max_pipelines_per_repo)
            except RuntimeError as e:
                print(f"[WARN] Pipelines fetch failed for {rslug}: {e}")
                pipelines = []

            for p in pipelines:
                puid = p.get("uuid")
                state = safe_get(p, "state", "name")
                created_on = p.get("created_on")
                target_ref = safe_get(p, "target", "ref_name") or safe_get(p, "target", "branch", "name")
                commit = safe_get(p, "target", "commit", "hash")
                build_number = p.get("build_number")
                duration = safe_get(p, "duration_in_seconds")
                pipelines_rows.append([
                    client.workspace,
                    safe_get(r, "project", "key"),
                    rslug,
                    puid,
                    build_number,
                    state,
                    target_ref,
                    commit,
                    created_on,
                    duration,
                ])
                self.edges.append(("repo", rslug, "pipeline", str(build_number or puid), "runs"))

                # Steps
                try:
                    steps = client.list_pipeline_steps(rslug, puid)
                except RuntimeError as e:
                    print(f"[WARN] Steps fetch failed for pipeline {puid} in {rslug}: {e}")
                    steps = []
                for s in steps:
                    steps_rows.append([
                        client.workspace,
                        rslug,
                        puid,
                        s.get("uuid"),
                        safe_get(s, "state", "name"),
                        safe_get(s, "name"),
                        safe_get(s, "duration_in_seconds"),
                    ])

            # Optional: fetch the bitbucket-pipelines.yml (best-effort)
            if self.opts.include_pipeline_yaml:
                content = client.get_file_from_default(rslug, "bitbucket-pipelines.yml")
                if content is not None:
                    yaml_rows.append([client.workspace, safe_get(r, "project", "key"), rslug, len(content)])
                    # Save per-repo yaml to outdir/yaml/
                    yaml_dir = os.path.join(self.outdir, "yaml")
                    ensure_outdir(yaml_dir)
                    with open(os.path.join(yaml_dir, f"{rslug}_bitbucket-pipelines.yml"), "w", encoding="utf-8") as f:
                        f.write(content)

        # Write CSVs
        print("[Cloud] Writing CSVs…")
        write_csv(os.path.join(self.outdir, "projects.csv"),
                  ["workspace", "project_key", "project_name", "project_uuid"],
                  ([client.workspace, p.get("key"), p.get("name"), p.get("uuid")] for p in projects))

        write_csv(os.path.join(self.outdir, "repos.csv"),
                  ["workspace", "project_key", "repo_slug", "repo_name", "repo_uuid", "is_private", "default_branch"],
                  (
                      [client.workspace,
                       safe_get(r, "project", "key"),
                       r.get("slug") or r.get("name"),
                       r.get("name"),
                       r.get("uuid"),
                       r.get("is_private", True),
                       client.get_default_branch_name(r)]
                      for r in all_repos
                  ))

        write_csv(os.path.join(self.outdir, "branches.csv"),
                  ["workspace", "project_key", "repo_slug", "branch_name", "commit_hash", "is_default", "date"],
                  branches_rows)

        write_csv(os.path.join(self.outdir, "pipelines.csv"),
                  ["workspace", "project_key", "repo_slug", "pipeline_uuid", "build_number", "state", "target_ref", "commit", "created_on", "duration_seconds"],
                  pipelines_rows)

        write_csv(os.path.join(self.outdir, "pipeline_steps.csv"),
                  ["workspace", "repo_slug", "pipeline_uuid", "step_uuid", "state", "name", "duration_seconds"],
                  steps_rows)

        write_csv(os.path.join(self.outdir, "variables.csv"),
                  ["scope", "workspace", "repo_slug", "var_uuid", "key", "secured", "type"],
                  var_rows)

        if self.opts.include_pipeline_yaml:
            write_csv(os.path.join(self.outdir, "pipeline_yaml_present.csv"),
                      ["workspace", "project_key", "repo_slug", "bytes"],
                      yaml_rows)

        # JSON summary
        summary = {
            "mode": "cloud",
            "workspace": client.workspace,
            "generated": iso_now(),
            "counts": {
                "projects": len(projects),
                "repos": len(all_repos),
                "pipelines_rows": len(pipelines_rows),
                "variables_rows": len(var_rows),
                "branches_rows": len(branches_rows),
            },
        }
        write_json(os.path.join(self.outdir, "summary.json"), summary)

    # -------- Server/DC path --------
    def run_server(self, client: BitbucketServerClient, project_keys: Optional[List[str]] = None) -> None:
        print("[Server/DC] Fetching projects…")
        projects = client.list_projects()
        if project_keys:
            projects = [p for p in projects if p.get("key") in set(project_keys)]

        all_repos: List[Dict[str, Any]] = []
        branches_rows: List[List[Any]] = []
        webhooks_rows: List[List[Any]] = []

        print("[Server/DC] Fetching repos & branches…")
        for p in projects:
            pkey = p.get("key")
            repos = client.list_repos(pkey)
            for r in repos:
                all_repos.append({
                    **r,
                    "project_key": pkey,
                })
                rslug = r.get("slug") or r.get("name")
                self.edges.append(("project", pkey, "repo", rslug, "contains"))

                # Branches
                try:
                    branches = client.list_branches(pkey, rslug)
                except RuntimeError as e:
                    print(f"[WARN] Branches fetch failed for {pkey}/{rslug}: {e}")
                    branches = []
                for b in branches:
                    branches_rows.append([
                        client.base,
                        pkey,
                        rslug,
                        b.get("displayId") or b.get("id"),
                        safe_get(b, "latestCommit"),
                        False,
                        None,
                    ])

                # Webhooks (best-effort)
                hooks = client.list_webhooks(pkey, rslug)
                for h in hooks:
                    webhooks_rows.append([
                        client.base,
                        pkey,
                        rslug,
                        h.get("id"),
                        h.get("name"),
                        h.get("url"),
                        ",".join(h.get("events", [])),
                        h.get("active", True),
                    ])

        # Write CSVs
        print("[Server/DC] Writing CSVs…")
        write_csv(os.path.join(self.outdir, "projects.csv"),
                  ["base_url", "project_key", "project_name", "public"],
                  ([client.base, p.get("key"), p.get("name"), p.get("public", False)] for p in projects))

        write_csv(os.path.join(self.outdir, "repos.csv"),
                  ["base_url", "project_key", "repo_slug", "repo_name", "scmId"],
                  ([client.base, r.get("project_key"), r.get("slug") or r.get("name"), r.get("name"), r.get("scmId")] for r in all_repos))

        write_csv(os.path.join(self.outdir, "branches.csv"),
                  ["base_url", "project_key", "repo_slug", "branch_name", "latest_commit", "is_default", "date"],
                  branches_rows)

        write_csv(os.path.join(self.outdir, "webhooks.csv"),
                  ["base_url", "project_key", "repo_slug", "hook_id", "name", "url", "events", "active"],
                  webhooks_rows)

        summary = {
            "mode": "server_dc",
            "base_url": client.base,
            "generated": iso_now(),
            "counts": {
                "projects": len(projects),
                "repos": len(all_repos),
                "branches_rows": len(branches_rows),
                "webhooks_rows": len(webhooks_rows),
            },
            "note": "Bitbucket Pipelines are a Cloud-only feature; Server/DC does not support native pipelines",
        }
        write_json(os.path.join(self.outdir, "summary.json"), summary)

    # -------- Relationships & Graph --------
    def write_relationships(self) -> None:
        if not self.edges:
            return
        write_csv(os.path.join(self.outdir, "relationships.csv"),
                  ["parent_type", "parent_id", "child_type", "child_id", "label"],
                  self.edges)

    def write_graphviz(self, title: str = "Bitbucket_Inventory") -> None:
        if not self.opts.graph or not self.edges:
            return
        dot_path = os.path.join(self.outdir, "inventory_graph.dot")
        with open(dot_path, "w", encoding="utf-8") as f:
            f.write("digraph Bitbucket {\n")
            f.write("  graph [label=\"" + title + "\", labelloc=t, fontsize=20];\n")
            f.write("  node [shape=box, style=filled, fillcolor=lightgrey];\n")
            for parent_type, parent_id, child_type, child_id, label in self.edges:
                pnode = f"{parent_type}:{parent_id}".replace("\"", "'")
                cnode = f"{child_type}:{child_id}".replace("\"", "'")
                f.write(f'  "{pnode}" -> "{cnode}" [label="{label}"];\n')
            f.write("}\n")
        # Try to render with graphviz if available
        try:
            import subprocess
            png_path = os.path.join(self.outdir, "inventory_graph.png")
            subprocess.run(["dot", "-Tpng", dot_path, "-o", png_path], check=True)
            print(f"[GraphViz] PNG written: {png_path}")
        except Exception:
            print("[GraphViz] 'dot' not found or failed; .dot file still written.")


# -----------------------------
# CLI
# -----------------------------

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Inventory Bitbucket (Cloud or Server/DC) and export relationships")

    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--cloud", action="store_true", help="Target Bitbucket Cloud")
    mode.add_argument("--server", action="store_true", help="Target Bitbucket Server/Data Center")

    # Cloud auth / params
    p.add_argument("--workspace", help="Bitbucket Cloud workspace slug")
    p.add_argument("--username", help="Username for Bitbucket (Cloud or Server/DC)")
    p.add_argument("--app-password", dest="app_password", help="Bitbucket Cloud App Password (use with --cloud)")
    p.add_argument("--access-token", dest="access_token", help="Bitbucket Cloud Access Token (Bearer)")

    # Server/DC auth / params
    p.add_argument("--base-url", help="Bitbucket Server/DC base URL, e.g. https://bitbucket.example.com")
    p.add_argument("--password", help="Password or Personal Access Token (Server/DC)")
    p.add_argument("--project-keys", nargs="*", help="Optional list of project keys to include (Server/DC)")
    p.add_argument("--verify-ssl", default="true", choices=["true", "false"], help="Verify SSL for Server/DC (default: true)")

    # Common
    p.add_argument("--out", default="./bitbucket_inventory_out", help="Output directory (default: ./bitbucket_inventory_out)")
    p.add_argument("--graph", action="store_true", help="Emit GraphViz .dot and try to render .png with 'dot'")

    # Cloud extras
    p.add_argument("--include-pipeline-yaml", action="store_true", help="Attempt to fetch bitbucket-pipelines.yml per repo (Cloud)")
    p.add_argument("--max-pipelines-per-repo", type=int, default=None, help="Limit pipelines fetched per repo (Cloud)")

    p.add_argument("--config", help="Path to INI config file (optional)")

    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    outdir = args.out
    ensure_outdir(outdir)
    opts = InventoryOptions(
        include_pipeline_yaml=args.include_pipeline_yaml,
        graph=args.graph,
        max_pipelines_per_repo=args.max_pipelines_per_repo,
    )
    runner = InventoryRunner(outdir, opts)

    if args.cloud:
        # Resolve values from args > env > config
        cfg = load_config(config_candidates(getattr(args, "config", None)))
        workspace = first_nonempty(
            args.workspace,
            os.getenv("BB_WORKSPACE"),
            cfg_get(cfg, "cloud", "workspace"),
        )
        username = first_nonempty(
            args.username,
            os.getenv("BB_USERNAME"),
            cfg_get(cfg, "cloud", "username"),
        )
        app_password = first_nonempty(
            args.app_password,
            os.getenv("BB_APP_PASSWORD"),
            cfg_get(cfg, "cloud", "app_password"),
        )
        access_token = first_nonempty(
            getattr(args, "access_token", None),
            os.getenv("BB_ACCESS_TOKEN"),
            cfg_get(cfg, "cloud", "access_token"),
        )
        if not workspace:
            print("Missing Cloud workspace. Provide --workspace or set BB_WORKSPACE or [cloud].workspace in auth.ini.", file=sys.stderr)
            return 2
        if not (access_token or (username and app_password)):
            print("Missing Cloud credentials. Provide --access-token OR --username and --app-password (or set env/auth.ini).", file=sys.stderr)
            return 2
        client = BitbucketCloudClient(
            workspace=workspace,
            username=username,
            app_password=app_password,
            access_token=access_token,
        )
        runner.run_cloud(client)

    elif args.server:
        # Resolve values from args > env > config
        cfg = load_config(config_candidates(getattr(args, "config", None)))
        base_url = first_nonempty(
            args.base_url,
            os.getenv("BB_BASE_URL"),
            cfg_get(cfg, "server", "base_url"),
        )
        username = first_nonempty(
            args.username,
            os.getenv("BB_SERVER_USERNAME"),
            cfg_get(cfg, "server", "username"),
            cfg_get(cfg, "server", "server_username"),
        )
        password = first_nonempty(
            args.password,
            os.getenv("BB_SERVER_PASSWORD"),
            cfg_get(cfg, "server", "password"),
        )
        verify_ssl = asbool(
            first_nonempty(
                args.verify_ssl,
                os.getenv("BB_VERIFY_SSL"),
                cfg_get(cfg, "server", "verify_ssl"),
            ),
            default=True,
        )
        project_keys_raw = first_nonempty(
            " ".join(args.project_keys) if args.project_keys else None,
            cfg_get(cfg, "server", "project_keys"),
        )
        project_keys = project_keys_raw.split() if project_keys_raw else None

        pairs = [
            ("base_url", base_url),
            ("username", username),
            ("password", password),
        ]
        missing = [k for k, v in pairs if not v]
        if missing:
            print(f"Missing required Server/DC params: {', '.join(missing)} (use flags/env/auth.ini)", file=sys.stderr)
            return 2
        client = BitbucketServerClient(base_url=base_url, username=username, password=password, verify_ssl=verify_ssl)
        runner.run_server(client, project_keys=project_keys)


    # Relationships and graph common write
    runner.write_relationships()
    runner.write_graphviz(title="Bitbucket Inventory")

    print(f"\nDone. Outputs written under: {os.path.abspath(outdir)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())