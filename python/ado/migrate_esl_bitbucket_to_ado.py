#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
migrate_esl_bitbucket_to_ado.py
--------------------------------
ESL-focused migration tool with robust fallbacks:
- Lists ESL repos in a Bitbucket workspace (via REST API)
- Mirrors Git history Bitbucket -> Azure DevOps (ADO)
- If local Git push to ADO fails, automatically triggers **ADO server-side import**
- Optionally converts bitbucket-pipelines.yml -> azure-pipelines.yml
- If Git clone to ADO repo fails, writes YAML via **ADO Pushes API** (no Git client)
- Creates ADO pipelines
- Safe logging, IPv4 preference option, Git auto-detection, separate API vs Git usernames

Auth model:
- Bitbucket REST API: usually **Atlassian EMAIL + User API token**
- Bitbucket Git over HTTPS: **ACCOUNT USERNAME + same token**
  Use --bb-git-username or env BB_GIT_USERNAME to provide the account username.
"""

import argparse, base64, configparser, os, shutil, socket, subprocess, sys, tempfile, time
from pathlib import Path
from typing import Any, Dict, List, Optional
import pandas as pd
import requests

# ---------------- Network helpers ----------------
def apply_force_ipv4():
    orig_getaddrinfo = socket.getaddrinfo
    def getaddrinfo_ipv4(host, port, family=0, type=0, proto=0, flags=0):
        res = orig_getaddrinfo(host, port, family, type, proto, flags)
        v4 = [r for r in res if r[0] == socket.AF_INET]
        return v4 or res
    socket.getaddrinfo = getaddrinfo_ipv4

# ---------------- Shell helpers ----------------
def sh(cmd: List[str], cwd: Optional[str] = None, env: Optional[Dict[str, str]] = None, dry_run: bool = False):
    safe = []
    for c in cmd:
        if isinstance(c, str) and "Authorization: Basic " in c:
            safe.append("Authorization: Basic ***")
        else:
            safe.append(c)
    print("$ " + " ".join(safe) + (f"  (cwd={cwd})" if cwd else ""))
    if dry_run:
        return 0, "", ""
    p = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = p.communicate()
    if p.returncode != 0:
        if out:
            print(out)
        if err:
            print(err, file=sys.stderr)
    return p.returncode, out, err

def resolve_git_exe(user_path: Optional[str] = None) -> str:
    import shutil as _shutil
    candidates = []
    if user_path:
        candidates.append(user_path)
    which = _shutil.which("git")
    if which:
        candidates.append(which)
    candidates += [
        r"C:\Program Files\Git\cmd\git.exe",
        r"C:\Program Files\Git\bin\git.exe",
        r"C:\Program Files (x86)\Git\cmd\git.exe",
        r"C:\Program Files (x86)\Git\bin\git.exe",
    ]
    for c in candidates:
        if c and os.path.exists(c):
            return c
    raise FileNotFoundError("Git not found. Install Git for Windows or provide --git-exe.")

# ---------------- Formatting helpers ----------------
def _mask(s: Optional[str], show_last: int = 4) -> str:
    if not s:
        return "<empty>"
    s = str(s)
    if len(s) <= show_last:
        return "*" * len(s)
    return "*" * (len(s) - show_last) + s[-show_last:]

def make_basic(user: str, pwd: str) -> str:
    return base64.b64encode(f"{user}:{pwd}".encode("utf-8")).decode("ascii")

# ---------------- Bitbucket REST ----------------
def bb_api_get(url: str, auth: tuple, params=None, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    headers = headers or {}
    r = requests.get(url, auth=auth, params=params, headers=headers, timeout=45)
    r.raise_for_status()
    return r.json()

def bb_api_get_raw(url: str, auth: tuple, headers: Optional[Dict[str, str]] = None) -> Optional[str]:
    headers = headers or {}
    r = requests.get(url, auth=auth, headers=headers, timeout=45)
    if r.status_code == 200:
        return r.text
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return None

def detect_yaml_in_repo(bb_workspace: str, repo_slug: str, bb_auth: tuple) -> Dict[str, Optional[str]]:
    for path in ["azure-pipelines.yml","azure-pipelines.yaml","bitbucket-pipelines.yml","bitbucket-pipelines.yaml"]:
        url = f"https://api.bitbucket.org/2.0/repositories/{bb_workspace}/{repo_slug}/src/HEAD/{path}"
        txt = bb_api_get_raw(url, bb_auth)
        if txt is not None:
            return {"path": path, "content": txt}
    return {"path": None, "content": None}

# ---------------- Azure DevOps REST ----------------
API_GIT_REPOS = "7.2-preview.1"
API_PIPELINES = "7.2-preview.1"
API_VAR_GROUP = "7.2-preview.1"

def ado_api(method: str, url: str, pat: str, json_body: Optional[Dict] = None, verify: bool = True) -> Dict[str, Any]:
    headers = {"Content-Type": "application/json"}
    auth = requests.auth.HTTPBasicAuth("", pat)
    method = method.lower()
    if method == "get":
        r = requests.get(url, auth=auth, headers=headers, timeout=60, verify=verify)
    elif method == "post":
        r = requests.post(url, auth=auth, headers=headers, json=json_body, timeout=60, verify=verify)
    elif method == "put":
        r = requests.put(url, auth=auth, headers=headers, json=json_body, timeout=60, verify=verify)
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

def ensure_ado_repo(org: str, project: str, repo_name: str, pat: str, dry_run: bool=False, offline: bool=False) -> Dict[str, Any]:
    if dry_run or offline:
        print(f"[DRY-RUN] Would ensure/create ADO repo: {repo_name} in project {project}")
        return {"name": repo_name, "id": "DRYRUN"}
    base = f"https://dev.azure.com/{org}/{project}/_apis/git/repositories?api-version={API_GIT_REPOS}"
    repos = ado_api("get", base, pat)
    for r in repos.get("value", []):
        if r["name"].lower() == repo_name.lower():
            print(f"[ADO] Repo exists: {repo_name}")
            return r
    print(f"[ADO] Creating repo: {repo_name}")
    create_url = f"https://dev.azure.com/{org}/{project}/_apis/git/repositories?api-version={API_GIT_REPOS}"
    body = {"name": repo_name}
    return ado_api("post", create_url, pat, body)

def ado_create_pipeline(org: str, project: str, repo_id: str, repo_name: str, yaml_path: str, pat: str, dry_run: bool=False, offline: bool=False) -> Dict[str, Any]:
    if dry_run or offline:
        print(f"[DRY-RUN] Would create ADO pipeline for {repo_name} using {yaml_path}")
        return {"name": f"{repo_name}-pipeline", "id": "DRYRUN"}
    url = f"https://dev.azure.com/{org}/{project}/_apis/pipelines?api-version={API_PIPELINES}"
    body = {"name": f"{repo_name}-pipeline", "configuration": {"type": "yaml", "path": yaml_path, "repository": {"id": repo_id, "name": repo_name, "type": "azureReposGit"}}}
    return ado_api("post", url, pat, body)

def ado_import_repo(org: str, project: str, repo_id: str, src_url: str, bb_username: str, bb_password: str, pat: str, timeout_sec: int=900, poll_sec: int=5, dry_run: bool=False, offline: bool=False) -> bool:
    if dry_run or offline:
        print(f"[DRY-RUN] Would request ADO server-side import from {src_url}")
        return True
    url = f"https://dev.azure.com/{org}/{project}/_apis/git/repositories/{repo_id}/importRequests?api-version={API_GIT_REPOS}"
    body = {"parameters": {"gitSource": {"url": src_url}, "username": bb_username, "password": bb_password}}
    try:
        resp = ado_api("post", url, pat, body)
    except Exception as e:
        print(f"[ERROR] Failed to start ADO import: {e}")
        return False
    import_id = resp.get("importRequestId")
    if not import_id:
        print("[ERROR] ADO import did not return an importRequestId")
        return False
    status_url = f"https://dev.azure.com/{org}/{project}/_apis/git/repositories/{repo_id}/importRequests/{import_id}?api-version={API_GIT_REPOS}"
    elapsed = 0
    while elapsed < timeout_sec:
        time.sleep(poll_sec)
        elapsed += poll_sec
        try:
            s = ado_api("get", status_url, pat)
        except Exception as e:
            print(f"[WARN] Import status poll failed: {e}")
            continue
        st = (s.get("parameters") or {}).get("status") or s.get("status") or ""
        print(f"  [ADO Import] status: {st} (t+{elapsed}s)")
        if st.lower() in ("completed","succeeded","success"):
            print("[OK] ADO import completed.")
            return True
        if st.lower() in ("failed","abandoned","cancelled","canceled"):
            print(f"[ERROR] ADO import failed: {s}")
            return False
    print("[ERROR] ADO import timed out.")
    return False

def ado_get_repo_info(org: str, project: str, repo_id: str, pat: str) -> Dict[str, Any]:
    url = f"https://dev.azure.com/{org}/{project}/_apis/git/repositories/{repo_id}?api-version=7.0"
    return ado_api("get", url, pat)

def ado_get_branch_object_id(org: str, project: str, repo_id: str, branch: str, pat: str) -> Optional[str]:
    url = f"https://dev.azure.com/{org}/{project}/_apis/git/repositories/{repo_id}/refs?filter=heads/{branch}&api-version=7.0"
    data = ado_api("get", url, pat)
    vals = data.get("value", [])
    if vals:
        return vals[0].get("objectId")
    return None

def ado_upsert_file(org: str, project: str, repo_id: str, path: str, content: str, pat: str, branch: Optional[str]=None, message: str="Add/Update file") -> bool:
    repo_info = ado_get_repo_info(org, project, repo_id, pat)
    default_ref = repo_info.get("defaultBranch") or "refs/heads/master"
    ref_branch = branch or default_ref.replace("refs/heads/", "")
    ref_name = f"refs/heads/{ref_branch}"
    old_oid = ado_get_branch_object_id(org, project, repo_id, ref_branch, pat)
    if old_oid is None:
        old_oid = "0"*40
    url = f"https://dev.azure.com/{org}/{project}/_apis/git/repositories/{repo_id}/pushes?api-version=7.0"
    for change_type in ("add","edit"):
        body = {"refUpdates":[{"name": ref_name, "oldObjectId": old_oid}], "commits":[{"comment": message, "changes":[{"changeType": change_type, "item":{"path": path}, "newContent":{"content": content, "contentType":"rawtext"}}]}]}
        try:
            ado_api("post", url, pat, body)
            return True
        except Exception as e:
            if change_type == "add":
                continue
            print(f"[ERROR] Failed to upsert {path} via Pushes API: {e}")
            return False
    return False

def load_csv(path: Optional[str]) -> Optional[pd.DataFrame]:
    if not path:
        return None
    pth = Path(path)
    if not pth.exists():
        return None
    try:
        return pd.read_csv(pth)
    except Exception as e:
        print(f"CSV read failed for {path}: {e}")
        return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--bb-workspace", required=True)
    ap.add_argument("--bb-username", required=True)
    ap.add_argument("--bb-password", required=True)
    ap.add_argument("--bb-git-username")
    ap.add_argument("--bb-project-key", default="esl")
    ap.add_argument("--ado-org")
    ap.add_argument("--ado-project", required=True)
    ap.add_argument("--repos-csv", default="repos.csv")
    ap.add_argument("--projects-csv", default="projects.csv")
    ap.add_argument("--variables-csv", default="variables.csv")
    ap.add_argument("--convert-bb-yaml", action="store_true")
    ap.add_argument("--push-secrets", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--debug-auth", action="store_true")
    ap.add_argument("--ado-offline", action="store_true")
    ap.add_argument("--force-ipv4", action="store_true")
    ap.add_argument("--git-exe")
    ap.add_argument("--no-import-fallback", action="store_true")
    args = ap.parse_args()

    if args.force_ipv4:
        apply_force_ipv4()
        print("[NET] IPv4 preference enabled for Python HTTP stack.")

    bb_git_username = args.bb_git_username or os.environ.get("BB_GIT_USERNAME") or args.bb_username
    cfg = configparser.ConfigParser(); cfg.read(args.config)
    ado_org = (args.ado_org or cfg.get("ado","org",fallback="")).strip()
    ado_pat = cfg.get("ado","pat",fallback="").strip()

    if args.debug_auth:
        print(f"[DEBUG] Bitbucket workspace: '{args.bb_workspace}'")
        print(f"[DEBUG] Bitbucket API username: '{args.bb_username}'")
        print(f"[DEBUG] Bitbucket GIT username: '{bb_git_username}'")
        print(f"[DEBUG] Bitbucket password: '{_mask(args.bb_password)}'")
        print(f"[DEBUG] ADO org: '{ado_org}' (PAT: {_mask(ado_pat)})")
        print(f"[DEBUG] Flags: dry_run={args.dry_run}, ado_offline={args.ado_offline}, force_ipv4={args.force_ipv4}")

    if not all([ado_org, ado_pat]) and not (args.dry_run or args.ado_offline):
        print("Missing ADO org/PAT in config. Populate [ado] org and pat, or use --dry-run/--ado-offline.", file=sys.stderr)
        sys.exit(2)

    git_exe = resolve_git_exe(args.git_exe) if not args.dry_run else (args.git_exe or "git")
    print(f"[GIT] Using: {git_exe}")

    bb_api_auth = (args.bb_username, args.bb_password)
    try:
        data = bb_api_get(f"https://api.bitbucket.org/2.0/repositories/{args.bb_workspace}?pagelen=1", bb_api_auth)
        size = data.get("size", 0)
        print(f"[BB] Auth OK. Workspace '{args.bb_workspace}' visible repos on page 1: {size}")
    except requests.HTTPError as e:
        print(f"[ERROR] Bitbucket auth/list probe failed: {e}", file=sys.stderr)
        sys.exit(2)

    repos_df = load_csv(args.repos_csv)
    projects_df = load_csv(args.projects_csv)
    variables_df = load_csv(args.variables_csv)
    allowed_project_keys = set([args.bb_project_key.lower()])
    if projects_df is not None and "project_key" in projects_df.columns and "project_name" in projects_df.columns:
        esl_keys = projects_df[projects_df["project_name"].str.lower().eq("esl")]["project_key"].str.lower().unique().tolist()
        if esl_keys:
            allowed_project_keys = set(esl_keys)

    repo_rows: List[Dict[str, Any]] = []
    if repos_df is not None and {"workspace","project_key","repo_slug","repo_name"}.issubset(repos_df.columns):
        print("[INFO] Using repos from repos.csv (no API listing)")
        repo_rows = repos_df[repos_df["project_key"].str.lower().isin(allowed_project_keys)].to_dict(orient="records")
    else:
        print("[WARN] repos.csv missing/invalid; listing ESL repos from Bitbucket API")
        url = f"https://api.bitbucket.org/2.0/repositories/{args.bb_workspace}"
        params = {"pagelen": 100, "q": f"project.key~\"{args.bb_project_key}\""}
        while url:
            data = bb_api_get(url, bb_api_auth, params=params)
            for v in data.get("values", []):
                proj = v.get("project", {}).get("key", "").lower()
                if proj in allowed_project_keys:
                    repo_rows.append({"workspace": args.bb_workspace, "project_key": proj, "repo_slug": v["slug"], "repo_name": v["name"], "is_private": v.get("is_private", True), "default_branch": (v.get("mainbranch") or {}).get("name")})
            url = data.get("next")

    print(f"[INFO] ESL-scoped repos: {len(repo_rows)}")
    for r in repo_rows:
        print(f" - {r['repo_name']} ({r['repo_slug']})")

    work_dir = Path.cwd() / "bb_mirror_work"
    work_dir.mkdir(exist_ok=True)
    offline = args.ado_offline
    for row in repo_rows:
        repo_slug = row["repo_slug"]; repo_name = row["repo_name"]
        print("\n" + "="*80)
        print(f"Migrating repo: {repo_name}  (slug: {repo_slug})")
        repo_info = ensure_ado_repo(ado_org, args.ado_project, repo_name, ado_pat, dry_run=args.dry_run, offline=offline)
        ado_repo_id = repo_info.get("id", "")
        src_url = f"https://bitbucket.org/{args.bb_workspace}/{repo_slug}.git"
        dest_url = f"https://dev.azure.com/{ado_org}/{args.ado_project}/_git/{repo_name}"
        bb_git_basic = make_basic(bb_git_username, args.bb_password)
        ado_basic = make_basic("", ado_pat)
        push_ok = False
        if args.dry_run:
            mirror_dir = work_dir / f"{repo_slug}.git"
            print(f"[DRY-RUN] Would clone --mirror {src_url} -> {mirror_dir}")
            print(f"[DRY-RUN] Would set push URL to {dest_url} and push --mirror")
            push_ok = True
        else:
            mirror_dir = work_dir / f"{repo_slug}.git"
            if mirror_dir.exists():
                shutil.rmtree(mirror_dir)
            rc,_,_ = sh([git_exe, "-c", f"http.extraHeader=Authorization: Basic {bb_git_basic}", "clone", "--mirror", src_url, str(mirror_dir)])
            if rc != 0:
                print(f"[ERROR] Failed to clone mirror for {repo_slug}, trying ADO server-side import...")
                push_ok = False
            else:
                rc,_,_ = sh([git_exe, "remote", "set-url", "--push", "origin", dest_url], cwd=str(mirror_dir))
                rc,_,_ = sh([git_exe, "-c", f"http.extraHeader=Authorization: Basic {ado_basic}", "push", "--mirror"], cwd=str(mirror_dir))
                push_ok = (rc == 0)
        if not push_ok and not args.no_import_fallback and ado_repo_id and not (args.dry_run or offline):
            print("[FALLBACK] Using ADO server-side import (no local Git push).")
            ok = ado_import_repo(ado_org, args.ado_project, ado_repo_id, src_url, bb_git_username, args.bb_password, ado_pat)
            if not ok:
                print("[ERROR] ADO import fallback failed; skipping repo.")
                continue
        yaml = detect_yaml_in_repo(args.bb_workspace, repo_slug, bb_api_auth)
        yaml_path = yaml.get("path"); yaml_content = yaml.get("content")
        final_yaml_path = None
        if yaml_path and yaml_path.startswith("azure-pipelines"):
            final_yaml_path = yaml_path
        elif yaml_path and yaml_path.startswith("bitbucket-pipelines") and args.convert_bb_yaml:
            print("[NOTE] Copying bitbucket-pipelines file into repo as azure-pipelines.yml (review required).")
            final_yaml_path = "azure-pipelines.yml"
            header = "# WARNING: Auto-copied from bitbucket-pipelines.yml. Review for ADO compatibility.\n"
            content = header + (yaml_content or "")
            if not args.dry_run and not offline and ado_repo_id:
                # Try Git path first; if it fails (e.g., TLS resets), fallback to Pushes API
                use_pushes = False
                try:
                    with tempfile.TemporaryDirectory() as tmpdir:
                        rc,_,_ = sh([git_exe, "clone", f"https://dev.azure.com/{ado_org}/{args.ado_project}/_git/{repo_name}", tmpdir])
                        if rc != 0:
                            use_pushes = True
                        else:
                            from pathlib import Path as _P
                            (_P(tmpdir)/"azure-pipelines.yml").write_text(content, encoding="utf-8")
                            sh([git_exe, "add", "azure-pipelines.yml"], cwd=tmpdir)
                            sh([git_exe, "commit", "-m", "Add azure-pipelines.yml (auto-copied from Bitbucket)"], cwd=tmpdir)
                            sh([git_exe, "push"], cwd=tmpdir)
                except Exception:
                    use_pushes = True
                if use_pushes:
                    print("[FALLBACK] Writing azure-pipelines.yml via ADO Pushes API (no Git).")
                    ok = ado_upsert_file(ado_org, args.ado_project, ado_repo_id, "/azure-pipelines.yml", content, ado_pat, message="Add azure-pipelines.yml (auto-copied)")
                    if not ok:
                        print("[WARN] Could not add azure-pipelines.yml via Pushes API.")
        if final_yaml_path and ado_repo_id:
            try:
                ado_create_pipeline(ado_org, args.ado_project, ado_repo_id, repo_name, f"/{final_yaml_path}", ado_pat, dry_run=args.dry_run, offline=offline)
            except Exception as e:
                print(f"[WARN] Pipeline creation failed for {repo_name}: {e}")

    print("\nDone.")
    print("NOTE: If you used --convert-bb-yaml, review each azure-pipelines.yml for proper ADO syntax.")
    print("      Configure service connections and permissions as needed.")

if __name__ == "__main__":
    main()
