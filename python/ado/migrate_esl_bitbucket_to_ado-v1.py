
#!/usr/bin/env python3
"""
migrate_esl_bitbucket_to_ado.py

Migrates ESL project repositories (and pipeline-related bits) from Bitbucket Cloud
to Azure DevOps (ADO). It uses your local Git to mirror full history and the ADO/Bitbucket
REST APIs to create repos, pipelines, and variable groups.

Inputs
------
- A config INI with Bitbucket and ADO creds/urls (see migration_config.example.ini).
- CSV "analysis" files exported from your discovery step (optional but recommended),
  used to scope which repos/pipelines to migrate. If they are present in the working
  directory (or paths are given with flags), only ESL entities are migrated.

What it does
------------
1) Filters to ESL-only repos using /mnt/data/projects.csv and /mnt/data/repos.csv if available.
   Otherwise filters by --bb-project-key esl.
2) For each ESL repo:
   - Creates a new ADO repo if missing.
   - Mirrors the Git history (branches/tags) from Bitbucket -> ADO via `git clone --mirror` and `git push --mirror`.
3) Pipelines & YAML:
   - Looks for azure-pipelines.yml in the repo. If missing but bitbucket-pipelines.yml exists,
     it can optionally copy it as azure-pipelines.yml (disabled by default; conversion is not 1:1).
   - Creates an ADO pipeline pointing to the YAML in the repo.
4) Variables:
   - Reads variables.csv (if present) and creates an ADO Variable Group per repo (optional), copying non-secret values.
     Variables marked as secret must be re-entered by hand unless you opt-in to pass them (see flag).

Limitations / Manual steps
--------------------------
- Service connections and pipeline permissions are not auto-created.
- Bitbucket Pipelines syntax is not directly compatible with ADO YAML. This tool can copy the file
  but you should review/convert jobs/steps, images, and triggers.
- Any external integrations (e.g., container registries) should be reconfigured in ADO.

Usage
-----
python migrate_esl_bitbucket_to_ado.py --config migration_config.ini --ado-org YOUR_ORG --ado-project YOUR_PROJECT --bb-workspace YOUR_WS --dry-run
"""

import argparse
import configparser
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, Any, List, Optional

import requests
import pandas as pd

# ---------- Helpers ----------

def sh(cmd: List[str], cwd: Optional[str] = None, env: Optional[Dict[str,str]] = None, dry_run=False):
    print(f"$ {' '.join(cmd)}" + (f"  (cwd={cwd})" if cwd else ""))
    if dry_run:
        return 0, "", ""
    p = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = p.communicate()
    if p.returncode != 0:
        print(out)
        print(err, file=sys.stderr)
    return p.returncode, out, err

def bb_api_get(url: str, auth: tuple, params=None) -> Dict[str, Any]:
    r = requests.get(url, auth=auth, params=params)
    r.raise_for_status()
    return r.json()

def bb_api_get_raw(url: str, auth: tuple) -> Optional[str]:
    r = requests.get(url, auth=auth)
    if r.status_code == 200:
        return r.text
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return None

def ado_api(method: str, url: str, pat: str, json_body: Optional[Dict]=None) -> Dict[str, Any]:
    headers = {"Content-Type":"application/json"}
    auth = requests.auth.HTTPBasicAuth("", pat)
    if method.lower()=="get":
        r = requests.get(url, auth=auth, headers=headers)
    elif method.lower()=="post":
        r = requests.post(url, auth=auth, headers=headers, json=json_body)
    elif method.lower()=="put":
        r = requests.put(url, auth=auth, headers=headers, json=json_body)
    else:
        raise ValueError("Unsupported method")
    if r.status_code >= 400:
        raise RuntimeError(f"ADO API {method.upper()} {url} failed: {r.status_code} {r.text}")
    if r.text:
        try:
            return r.json()
        except Exception:
            return {"text": r.text}
    return {}

def ensure_ado_repo(org: str, project: str, repo_name: str, pat: str, dry_run=False) -> Dict[str,Any]:
    # Check if repo exists
    base = f"https://dev.azure.com/{org}/{project}/_apis/git/repositories?api-version=7.1-preview.1"
    repos = ado_api("get", base, pat)
    for r in repos.get("value", []):
        if r["name"].lower() == repo_name.lower():
            print(f"[ADO] Repo exists: {repo_name}")
            return r
    # Create repo
    print(f"[ADO] Creating repo: {repo_name}")
    if dry_run:
        return {"name": repo_name, "id": "DRYRUN"}
    create_url = f"https://dev.azure.com/{org}/{project}/_apis/git/repositories?api-version=7.1-preview.1"
    body = {"name": repo_name, "project": {"name": project}}
    return ado_api("post", create_url, pat, body)

def ado_create_pipeline(org: str, project: str, repo_id: str, repo_name: str, yaml_path: str, pat: str, dry_run=False) -> Dict[str,Any]:
    # Create a minimal pipeline definition referencing the YAML in this repo
    print(f"[ADO] Creating pipeline for {repo_name} using {yaml_path}")
    if dry_run:
        return {"name": f"{repo_name}-pipeline", "id": "DRYRUN"}
    url = f"https://dev.azure.com/{org}/{project}/_apis/pipelines?api-version=7.1-preview.1"
    body = {
        "name": f"{repo_name}-pipeline",
        "configuration": {
            "type": "yaml",
            "path": yaml_path,
            "repository": {
                "id": repo_id,
                "name": repo_name,
                "type": "azureReposGit"
            }
        }
    }
    return ado_api("post", url, pat, body)

def ado_create_variable_group(org: str, project: str, pat: str, group_name: str, variables: Dict[str, Dict[str,Any]], dry_run=False) -> Dict[str,Any]:
    print(f"[ADO] Creating variable group: {group_name} with {len(variables)} vars")
    if dry_run:
        return {"id": "DRYRUN", "name": group_name}
    url = f"https://dev.azure.com/{org}/{project}/_apis/distributedtask/variablegroups?api-version=7.1-preview.1"
    body = {
        "type": "Vsts",
        "name": group_name,
        "variables": variables
    }
    return ado_api("post", url, pat, body)

def detect_yaml_in_repo(bb_workspace: str, repo_slug: str, bb_auth: tuple) -> Dict[str, Optional[str]]:
    # Try root-level common names
    for path in ["azure-pipelines.yml", "azure-pipelines.yaml", "bitbucket-pipelines.yml", "bitbucket-pipelines.yaml"]:
        url = f"https://api.bitbucket.org/2.0/repositories/{bb_workspace}/{repo_slug}/src/HEAD/{path}"
        txt = bb_api_get_raw(url, bb_auth)
        if txt is not None:
            return {"path": path, "content": txt}
    return {"path": None, "content": None}

def load_csv(path: Optional[str]) -> Optional[pd.DataFrame]:
    if not path:
        return None
    p = Path(path)
    if not p.exists():
        return None
    try:
        return pd.read_csv(p)
    except Exception as e:
        print(f"CSV read failed for {path}: {e}")
        return None

# ---------- Main ----------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True, help="Path to INI with [bitbucket] and [ado]")
    ap.add_argument("--bb-workspace", help="Bitbucket workspace (overrides config)")
    ap.add_argument("--bb-project-key", default="esl", help="Bitbucket project key to filter (default: esl)")
    ap.add_argument("--ado-org", help="ADO organization (overrides config)")
    ap.add_argument("--ado-project", required=True, help="ADO project to migrate into")
    ap.add_argument("--repos-csv", default="repos.csv", help="Path to repos.csv")
    ap.add_argument("--projects-csv", default="projects.csv", help="Path to projects.csv")
    ap.add_argument("--variables-csv", default="variables.csv", help="Path to variables.csv")
    ap.add_argument("--pipelines-csv", default="pipelines.csv", help="Path to pipelines.csv")
    ap.add_argument("--convert-bb-yaml", action="store_true", help="If no azure-pipelines.yml, copy bitbucket-pipelines.yml to azure-pipelines.yml")
    ap.add_argument("--push-secrets", action="store_true", help="If variables.csv marks secrets, include them (use with caution)")
    ap.add_argument("--dry-run", action="store_true", help="Plan only, no changes")
    args = ap.parse_args()

    # Read config
    cfg = configparser.ConfigParser()
    cfg.read(args.config)

    bb_workspace = args.bb_workspace or cfg.get("bitbucket", "workspace", fallback=None)
    bb_user = cfg.get("bitbucket", "username", fallback=None)
    bb_app_password = cfg.get("bitbucket", "app_password", fallback=None)
    bb_base_url = cfg.get("bitbucket", "base_url", fallback="https://bitbucket.org")

    ado_org = args.ado_org or cfg.get("ado", "org", fallback=None)
    ado_pat = cfg.get("ado", "pat", fallback=None)
    ado_base_url = cfg.get("ado", "base_url", fallback="https://dev.azure.com")

    if not all([bb_workspace, bb_user, bb_app_password, ado_org, ado_pat]):
        print("Missing required config values. See migration_config.example.ini", file=sys.stderr)
        sys.exit(2)

    bb_auth = (bb_user, bb_app_password)

    # Load CSVs
    repos_df = load_csv(args.repos_csv)
    projects_df = load_csv(args.projects_csv)
    variables_df = load_csv(args.variables_csv)

    # Determine ESL filter from projects.csv
    allowed_project_keys = set([args.bb_project_key.lower()])
    if projects_df is not None:
        if "project_key" in projects_df.columns:
            esl_keys = projects_df[projects_df["project_name"].str.lower().eq("esl")]["project_key"].str.lower().unique().tolist() if "project_name" in projects_df.columns else []
            if esl_keys:
                allowed_project_keys = set(esl_keys)

    # Build repo list
    repo_rows: List[Dict[str,Any]] = []
    if repos_df is not None and {"workspace","project_key","repo_slug","repo_name"}.issubset(repos_df.columns):
        repo_rows = repos_df[repos_df["project_key"].str.lower().isin(allowed_project_keys)].to_dict(orient="records")
    else:
        # Fallback: discover from Bitbucket API
        print("[WARN] repos.csv missing/invalid; listing repos from Bitbucket API")
        url = f"https://api.bitbucket.org/2.0/repositories/{bb_workspace}"
        pagelen = 100
        params = {"pagelen": pagelen, "q": f"project.key~\"{args.bb_project_key}\""}
        while url:
            data = bb_api_get(url, bb_auth, params=params)
            for v in data.get("values", []):
                proj = v.get("project", {}).get("key","").lower()
                if proj in allowed_project_keys:
                    repo_rows.append({
                        "workspace": bb_workspace,
                        "project_key": proj,
                        "repo_slug": v["slug"],
                        "repo_name": v["name"],
                        "is_private": v.get("is_private", True),
                        "default_branch": (v.get("mainbranch") or {}).get("name")
                    })
            url = data.get("next")

    print(f"[INFO] ESL-scoped repos: {len(repo_rows)}")
    for r in repo_rows:
        print(f" - {r['repo_name']} ({r['repo_slug']})")

    # Work dir
    work_dir = Path.cwd() / "bb_mirror_work"
    work_dir.mkdir(exist_ok=True)

    # Process each repo
    for row in repo_rows:
        repo_slug = row["repo_slug"]
        repo_name = row["repo_name"]
        print("\n" + "="*80)
        print(f"Migrating repo: {repo_name}  (slug: {repo_slug})")

        # 1) Ensure ADO repo
        repo_info = ensure_ado_repo(ado_org, args.ado_project, repo_name, ado_pat, dry_run=args.dry_run)
        ado_repo_id = repo_info.get("id", "")

        # 2) Git mirror push
        # Bitbucket clone URL: https://bitbucket.org/{workspace}/{slug}.git
        # ADO push URL: https://{org}@dev.azure.com/{org}/{project}/_git/{repo_name}
        src_url = f"https://bitbucket.org/{bb_workspace}/{repo_slug}.git"
        dest_url = f"https://{ado_org}@dev.azure.com/{ado_org}/{args.ado_project}/_git/{repo_name}"

        mirror_dir = work_dir / f"{repo_slug}.git"
        if mirror_dir.exists():
            shutil.rmtree(mirror_dir)

        rc, _, _ = sh(["git", "clone", "--mirror", src_url, str(mirror_dir)], dry_run=args.dry_run)
        if rc != 0 and not args.dry_run:
            print(f"[ERROR] Failed to clone mirror for {repo_slug}, skipping")
            continue

        # Set credentials helper for push (use PAT via url embedding)
        # For security, let user be prompted or rely on credential manager; we only print the dest URL without PAT.
        rc, _, _ = sh(["git", "remote", "set-url", "--push", "origin", dest_url], cwd=str(mirror_dir), dry_run=args.dry_run)
        rc, _, _ = sh(["git", "push", "--mirror"], cwd=str(mirror_dir), dry_run=args.dry_run)

        # 3) YAML detection and optional conversion
        yaml = detect_yaml_in_repo(bb_workspace, repo_slug, bb_auth)
        yaml_path = yaml.get("path")
        yaml_content = yaml.get("content")

        # If we found azure-pipelines.yml, create pipeline
        final_yaml_path = None
        if yaml_path and yaml_path.startswith("azure-pipelines"):
            final_yaml_path = yaml_path
        elif yaml_path and yaml_path.startswith("bitbucket-pipelines") and args.convert_bb_yaml:
            # naive copy: add the file into the ADO repo
            print("[NOTE] Copying bitbucket-pipelines file into repo as azure-pipelines.yml (review required).")
            if not args.dry_run:
                with tempfile.TemporaryDirectory() as tmpdir:
                    # shallow clone ADO repo, add file, commit, push
                    rc, _, _ = sh(["git", "clone", f"https://{ado_org}@dev.azure.com/{ado_org}/{args.ado_project}/_git/{repo_name}", tmpdir])
                    azp = Path(tmpdir) / "azure-pipelines.yml"
                    azp.write_text(yaml_content or "")
                    # Commit with a warning header
                    # Prepend a header comment
                    txt = azp.read_text()
                    header = (
                        "# WARNING: This file was auto-copied from bitbucket-pipelines.yml.\n"
                        "# You must review/convert steps, images, and triggers for ADO compatibility.\n"
                    )
                    azp.write_text(header + txt)
                    rc, _, _ = sh(["git", "add", "azure-pipelines.yml"], cwd=tmpdir)
                    rc, _, _ = sh(["git", "commit", "-m", "Add azure-pipelines.yml (auto-copied from Bitbucket)"], cwd=tmpdir)
                    rc, _, _ = sh(["git", "push"], cwd=tmpdir)
            final_yaml_path = "azure-pipelines.yml"

        # 4) Create ADO pipeline if we have a YAML path
        if final_yaml_path and ado_repo_id:
            try:
                ado_create_pipeline(ado_org, args.ado_project, ado_repo_id, repo_name, f"/{final_yaml_path}", ado_pat, dry_run=args.dry_run)
            except Exception as e:
                print(f"[WARN] Pipeline creation failed for {repo_name}: {e}")

        # 5) Variables -> Variable Group (optional, requires variables.csv)
        if variables_df is not None and not variables_df.empty:
            # Expect columns: workspace, project_key, repo_slug, name, value, is_secret?
            cols = set([c.lower() for c in variables_df.columns])
            if {"workspace","project_key","repo_slug","name","value"}.issubset(cols):
                sub = variables_df[(variables_df["project_key"].str.lower().isin(allowed_project_keys)) & (variables_df["repo_slug"]==repo_slug)]
                if not sub.empty:
                    vg_name = f"{repo_name}-migrated-vars"
                    var_map = {}
                    for _, rowv in sub.iterrows():
                        name = str(rowv["name"])
                        value = "" if (str(rowv.get("value","")) in [None,"nan"]) else str(rowv.get("value",""))
                        is_secret = False
                        if "is_secret" in sub.columns:
                            is_secret = bool(rowv.get("is_secret", False))
                        if is_secret and not args.push_secrets:
                            # create placeholder
                            var_map[name] = {"isSecret": True, "value": ""}
                        else:
                            var_map[name] = {"isSecret": bool(is_secret), "value": value}
                    try:
                        ado_create_variable_group(ado_org, args.ado_project, ado_pat, vg_name, var_map, dry_run=args.dry_run)
                    except Exception as e:
                        print(f"[WARN] Variable group creation failed for {repo_name}: {e}")
            else:
                print("[WARN] variables.csv missing required columns; skipping variable migration.")

    print("\nDone.")
    print("NOTE: If you used --convert-bb-yaml, review each azure-pipelines.yml for proper ADO syntax.")
    print("      Also configure service connections and permissions as needed.")

if __name__ == "__main__":
    main()
