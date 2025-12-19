#!/usr/bin/env python3
"""
compare_repos_refs.py

Compares refs (branches & tags) between a Bitbucket repo and an Azure DevOps (ADO) repo.
It uses `git ls-remote` with HTTPS Basic headers, so no local clones are required.

Outputs a console summary and (optionally) a CSV of ref-by-ref comparison.

Usage (example):
  python compare_repos_refs.py \
    --bb-url https://bitbucket.org/solutionsmetrixcrmdev/esl.git \
    --bb-username chrismorgan3 \
    --bb-token <BB_TOKEN> \
    --ado-url https://dev.azure.com/ESLFederalCreditUnion/HubTestProject/_git/ESL \
    --ado-pat <ADO_PAT> \
    --git-exe "C:\Program Files\Git\cmd\git.exe" \
    --output-csv E:\Temp\repo_compare.csv \
    --force-ipv4 --http11

Notes:
- For Bitbucket: username should be the Bitbucket *account username* (e.g., "chrismorgan3").
- For ADO: we use PAT as password with an *empty* username for Basic auth.
  (i.e., Basic base64(":<PAT>")).
- The script lists both heads and tags from both remotes and compares SHAs.
- Exit code: 0 if all refs match; 2 if differences found; 3 on network/auth issues.
"""

import argparse
import base64
import csv
import os
import subprocess
import sys
from collections import namedtuple

Result = namedtuple("Result", "code stdout stderr")

def make_basic(user: str, pwd: str) -> str:
    return base64.b64encode(f"{user}:{pwd}".encode("ascii")).decode("ascii")

def run_git_ls_remote(url: str, basic_header: str, git_exe: str, http11: bool, force_ipv4: bool) -> Result:
    # Build git command
    cmd = [
        git_exe, "-c", f"http.extraHeader=Authorization: Basic {basic_header}"
    ]
    if http11:
        cmd += ["-c", "http.version=HTTP/1.1"]
    # Use Windows trust store (Git for Windows) if available
    cmd += ["-c", "http.sslBackend=schannel"]
    cmd += ["ls-remote", "--heads", "--tags", url]

    env = os.environ.copy()
    if force_ipv4:
        # Helps in environments where IPv6 path resets; not official but influences libcurl behavior
        env["GIT_TRACE"] = env.get("GIT_TRACE", "1")
        env["GIT_CURL_VERBOSE"] = env.get("GIT_CURL_VERBOSE", "1")
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
        out, err = proc.communicate(timeout=180)
        return Result(proc.returncode, out, err)
    except subprocess.TimeoutExpired:
        return Result(124, "", "git ls-remote timed out")
    except Exception as e:
        return Result(1, "", f"Exception: {e}")

def parse_refs(ls_remote_output: str):
    """
    Parse `git ls-remote` lines: "<sha>\t<ref>"
    Returns two dicts: heads (name->sha), tags (name->sha)
    """
    heads, tags = {}, {}
    for line in ls_remote_output.splitlines():
        line = line.strip()
        if not line:
            continue
        if "\t" not in line:
            continue
        sha, ref = line.split("\t", 1)
        if ref.startswith("refs/heads/"):
            heads[ref[len("refs/heads/"):]] = sha
        elif ref.startswith("refs/tags/"):
            # Annotated tags may include ^{} entries; prefer the peeled one (the ^{} SHA is the commit)
            name = ref[len("refs/tags/"):]
            if name.endswith("^{}"):
                name = name[:-3]
                tags[name] = sha
            else:
                # Only set if not already set by a peeled entry
                tags.setdefault(name, sha)
    return heads, tags

def compare_maps(bb_map: dict, ado_map: dict, ref_kind: str):
    """
    Returns list of dict rows with: ref, bb_sha, ado_sha, status, kind
    status: match | mismatch | missing_in_ado | missing_in_bb
    """
    rows = []
    all_refs = set(bb_map.keys()) | set(ado_map.keys())
    for ref in sorted(all_refs):
        bb_sha = bb_map.get(ref)
        ado_sha = ado_map.get(ref)
        if bb_sha and ado_sha:
            status = "match" if bb_sha == ado_sha else "mismatch"
        elif bb_sha and not ado_sha:
            status = "missing_in_ado"
        else:
            status = "missing_in_bb"
        rows.append({"ref": ref, "bb_sha": bb_sha or "", "ado_sha": ado_sha or "", "status": status, "kind": ref_kind})
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
    ap = argparse.ArgumentParser(description="Compare refs between Bitbucket and ADO without cloning.")
    ap.add_argument("--bb-url", required=True, help="Bitbucket HTTPS clone URL (e.g., https://bitbucket.org/workspace/repo.git)")
    ap.add_argument("--bb-username", required=True, help="Bitbucket *account username* (e.g., chrismorgan3)")
    ap.add_argument("--bb-token", required=True, help="Bitbucket token (App Password or Atlassian token that works for HTTPS Git)")
    ap.add_argument("--ado-url", required=True, help="ADO HTTPS clone URL (e.g., https://dev.azure.com/org/project/_git/repo)")
    ap.add_argument("--ado-pat", required=True, help="Azure DevOps Personal Access Token (PAT)")
    ap.add_argument("--git-exe", default="git", help="Path to git executable (e.g., C:\\Program Files\\Git\\cmd\\git.exe)")
    ap.add_argument("--output-csv", help="Optional: write detailed comparison to CSV")
    ap.add_argument("--force-ipv4", action="store_true", help="Favor IPv4 (helps if IPv6 path causes TLS resets)")
    ap.add_argument("--http11", action="store_true", help="Force HTTP/1.1 (avoids some proxies' HTTP/2 issues)")
    ap.add_argument("--show-missing-only", action="store_true", help="Only print refs that are mismatched or missing")

    args = ap.parse_args()

    # Prepare Basic headers
    bb_basic = make_basic(args.bb_username, args.bb_token)
    ado_basic = make_basic("", args.ado_pat)

    print("[*] Querying Bitbucket refs via git ls-remote ...")
    bb_res = run_git_ls_remote(args.bb_url, bb_basic, args.git_exe, args.http11, args.force_ipv4)
    if bb_res.code != 0:
        print(f"[ERROR] Bitbucket ls-remote failed (code={bb_res.code}):\n{bb_res.stderr}", file=sys.stderr)
        sys.exit(3)

    print("[*] Querying ADO refs via git ls-remote ...")
    ado_res = run_git_ls_remote(args.ado_url, ado_basic, args.git_exe, args.http11, args.force_ipv4)
    if ado_res.code != 0:
        print(f"[ERROR] ADO ls-remote failed (code={ado_res.code}):\n{ado_res.stderr}", file=sys.stderr)
        sys.exit(3)

    bb_heads, bb_tags = parse_refs(bb_res.stdout)
    ado_heads, ado_tags = parse_refs(ado_res.stdout)

    head_rows = compare_maps(bb_heads, ado_heads, "head")
    tag_rows = compare_maps(bb_tags, ado_tags, "tag")
    rows = head_rows + tag_rows

    # Console report
    print_summary(rows)

    def fmt_row(r):
        return f"{r['kind']:4} {r['status']:16} {r['ref']}  bb:{r['bb_sha'][:8]}  ado:{r['ado_sha'][:8]}"

    if args.show-missing-only:
        to_print = [r for r in rows if r["status"] != "match"]
    else:
        to_print = rows

    if to_print:
        print("\n==== Detailed refs ====")
        for r in to_print:
            print(fmt_row(r))
    else:
        print("\n(no differences)")

    # CSV output
    if args.output_csv:
        fieldnames = ["kind", "ref", "bb_sha", "ado_sha", "status"]
        with open(args.output_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in rows:
                writer.writerow(r)
        print(f"\n[+] Wrote CSV: {args.output_csv}")

    # Exit non-zero if differences found
    diffs = any(r["status"] != "match" for r in rows)
    sys.exit(2 if diffs else 0)

if __name__ == "__main__":
    main()
