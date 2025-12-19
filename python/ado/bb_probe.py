# bb_probe.py
import base64, requests, os

MODE = os.getenv("BB_MODE", "basic")   # basic | bearer
WS   = "solutionsmetrixcrmdev"

if MODE == "basic":
    EMAIL   = os.getenv("BB_EMAIL")        # your Atlassian account email
    API_TOK = os.getenv("BB_API_TOKEN")    # user API token
    pair = f"{EMAIL}:{API_TOK}".encode("ascii")
    headers = {"Authorization": "Basic " + base64.b64encode(pair).decode("ascii")}
else:
    BEARER = os.getenv("BB_BEARER")        # workspace/repo access token
    headers = {"Authorization": f"Bearer {BEARER}"}

def get(u):
    r = requests.get(u, headers=headers, timeout=30)
    print(r.status_code, u)
    print(r.text[:300], "\n")
    return r

# Optional identity (will 401 on basic if token lacks Account:Read; that's OK)
if MODE == "basic":
    get("https://api.bitbucket.org/2.0/user")

# Authoritative repo test (bypasses workspace listing)
get(f"https://api.bitbucket.org/2.0/repositories/{WS}/esl")

# Workspace listing (may require membership)
get(f"https://api.bitbucket.org/2.0/repositories/{WS}?pagelen=1")
