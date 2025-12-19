
#!/usr/bin/env python3
"""
compare_repos_refs_v2.py

Compares refs (branches & tags) between Bitbucket (via `git ls-remote`) and Azure DevOps (via ADO REST API).
This avoids Git/libcurl for ADO to bypass local TLS/IPv6 resets.
"""

import argparse
import base64
import csv
import os
import subprocess
import sys
from collections import namedtuple
from typing import Dict

import json
import urllib.request
import urllib.error

Result = namedtuple("Result", "code stdout stderr")

def make_basic(user: str, pwd: str) -> str:
    return base64.b64encode(f"{user}:{pwd}".encode("ascii")).decode("ascii")

def run_git_ls_remote(url: str, basic_header: str, git_exe: str, http11: bool, force_ipv4: bool) -> Result:
    cmd = [git_exe, "-c", f"http.extraHeader=Authorization: Basic {basic_header}"]
    if http11:
        cmd += ["-c", "http.version=HTTP/1.1"]
    cmd += ["-c", "http.sslBackend=schannel", "ls-remote", "--heads", "--tags", url]

    env = os.environ.copy()
    if force_ipv4:
        env["GIT_TRACE"] = env.get("GIT_TRACE", "1")
        env["GIT_CURL_VERBOSE"] = env.get("GIT_CURL_VERBOSE", "1")

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
        out, err = proc.communicate(timeout=240)
        return Result(proc.returncode, out, err)
    except subprocess.TimeoutExpired:
        return Result(124, "", "git ls-remote timed out")
    except Exception as e:
        return Result(1, "", f"Exception: {e}")

def parse_refs_from_ls_remote(output: str):
    heads, tags = {}, {}
    for line in output.splitlines():
        line = line.strip()
        if not line or "\t" not in line:
            continue
        sha, ref = line.split("\t", 1)
        if ref.startswith("refs/heads/"):
            heads[ref[len("refs/heads/"):]] = sha
        elif ref.startswith("refs/tags/"):
            name = ref[len("refs/tags/"):]
            if name.endswith("^{}"):
                name = name[:-3]
                tags[name] = sha
            else:
                tags.setdefault(name, sha)
    return heads, tags

def ado_get_refs(org: str, project: str, repo: str, pat: str, filter_prefix: str) -> Dict[str, str]:
    base = f"https://dev.azure.com/{org}/{project}/_apis/git/repositories/{repo}/refs"
    url = f"{base}?filter={filter_prefix}/&peelTags=true&api-version=7.0"
    headers = {
        "Authorization": "Basic " + make_basic("", pat),
        "Content-Type": "application/json",
        "User-Agent": "RepoCompare/1.0"
    }
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=60) as r:
        data = json.loads(r.read().decode("utf-8"))

    result = {}
    for item in data.get("value", []):
        name = item.get("name", "")
        obj = item.get("objectId") or item.get("peeledObjectId") or ""
        if not name or not obj:
            continue
        if name.startswith("refs/heads/"):
            result[name[len("refs/heads/"):]] = obj
        elif name.startswith("refs/tags/"):
            result[name[len("refs/tags/"):]] = obj
    return result

def compare(bb: Dict[str, str], ado: Dict[str, str], kind: str):
    rows = []
    all_names = set(bb) | set(ado)
    for n in sorted(all_names):
        bb_sha = bb.get(n, "")
        ado_sha = ado.get(n, "")
        if bb_sha and ado_sha:
            status = "match" if bb_sha == ado_sha else "mismatch"
        elif bb_sha and not ado_sha:
            status = "missing_in_ado"
        else:
            status = "missing_in_bb"
        rows.append({"kind": kind, "ref": n, "bb_sha": bb_sha, "ado_sha": ado_sha, "status": status})
    return rows

def print_summary(rows):
    total = len(rows)
    matches = sum(1 for r in rows if r["status"] == "match")
    mism = sum(1 for r in rows if r["status"] == "mismatch")
    miss_ado = sum(1 for r in rows if r["status"] == "missing_in_ado")
    miss_bb = sum(1 for r in rows if r["status"] == "missing_in_bb")
    print("\n==== Comparison Summary ====")
    print(f"Total refs compared : {total}")
    print(f"Matches             : {matches}")
    print(f"Mismatches          : {mism}")
    print(f"Missing in ADO      : {miss_ado}")
    print(f"Missing in BB       : {miss_bb}")

def main():
    ap = argparse.ArgumentParser(description="Compare Bitbucket vs ADO refs using Bitbucket Git and ADO REST.")
    ap.add_argument("--bb-url", required=True)
    ap.add_argument("--bb-username", required=True)
    ap.add_argument("--bb-token", required=True)
    ap.add_argument("--ado-org", required=True)
    ap.add_argument("--ado-project", required=True)
    ap.add_argument("--ado-repo", required=True)
    ap.add_argument("--ado-pat", required=True)
    ap.add_argument("--git-exe", default="git")
    ap.add_argument("--output-csv")
    ap.add_argument("--force-ipv4", action="store_true")
    ap.add_argument("--http11", action="store_true")
    ap.add_argument("--show-missing-only", action="store_true")
    args = ap.parse_args()

    # Bitbucket refs
    print("[*] Querying Bitbucket refs via git ls-remote ...")
    bb_basic = make_basic(args.bb_username, args.bb_token)
    bb_res = run_git_ls_remote(args.bb_url, bb_basic, args.git_exe, args.http11, args.force_ipv4)
    if bb_res.code != 0:
        print(f"[ERROR] Bitbucket ls-remote failed (code={bb_res.code}):\n{bb_res.stderr}", file=sys.stderr)
        sys.exit(3)
    bb_heads, bb_tags = parse_refs_from_ls_remote(bb_res.stdout)

    # ADO refs via REST
    print("[*] Querying ADO refs via REST API ...")
    ado_heads = ado_get_refs(args.ado_org, args.ado_project, args.ado_repo, args.ado_pat, "refs/heads")
    ado_tags  = ado_get_refs(args.ado_org, args.ado_project, args.ado_repo, args.ado_pat, "refs/tags")

    rows = compare(bb_heads, ado_heads, "head") + compare(bb_tags, ado_tags, "tag")

    print_summary(rows)

    details = rows if not args.show-missing-only else [r for r in rows if r["status"] != "match"]
    if details:
        print("\n==== Detailed refs ====")
        for r in details:
            print(f"{r['kind']:4} {r['status']:16} {r['ref']}  bb:{r['bb_sha'][:8]}  ado:{r['ado_sha'][:8]}")
    else:
        print("\n(no differences)")

    if args.output_csv:
        with open(args.output_csv, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["kind","ref","bb_sha","ado_sha","status"])
            w.writeheader()
            for r in rows:
                w.writerow(r)
        print(f"\n[+] Wrote CSV: {args.output_csv}")

    diffs = any(r["status"] != "match" for r in rows)
    sys.exit(2 if diffs else 0)

if __name__ == "__main__":
    main()
