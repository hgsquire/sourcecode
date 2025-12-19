import requests
import configparser
import os
import urllib3
from datetime import datetime
from requests.auth import HTTPBasicAuth
import json
from tqdm import tqdm

# --- Disable SSL warnings ---
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Config ---
config_file = "jira_config.ini"
config = configparser.ConfigParser()
config.read(config_file)

instances = {
    section: config[section]["url"]
    for section in config.sections()
    if all(k in config[section] for k in ("url", "username", "pat"))
}

if not instances:
    print("No valid Jira instances found in the config file.")
    exit(1)

print("\nAvailable Jira instances:")
for i, k in enumerate(instances.keys(), 1):
    print(f"{i}. {k}")
choice = input("Select an instance: ").strip()
instance_name = list(instances.keys())[int(choice) - 1]

jira_url = config[instance_name]["url"]
username = config[instance_name]["username"]
pat = config[instance_name]["pat"]
auth = HTTPBasicAuth(username, pat)

# --- Prompt for project key and custom field ID ---
project_key = input("\nEnter the Jira project key: ").strip()
custom_field_id = input("Enter the custom field ID (e.g., customfield_10679): ").strip()

# --- Log file setup ---
log_file = f"log_results_{project_key}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
with open(log_file, "w", encoding="utf-8") as log:
    log.write(f"Issue update log for project {project_key}, field {custom_field_id}\n")
    log.write("-" * 50 + "\n")

# --- Helper: Check if ADF field is truly empty ---
def is_adf_field_empty(field):
    if not field:
        return True
    if isinstance(field, str):
        return not field.strip()
    if isinstance(field, dict):
        content = field.get("content", [])
        if not content:
            return True
        for block in content:
            if block.get("type") == "paragraph":
                inner = block.get("content", [])
                if inner and any(text.get("text", "").strip() for text in inner if text.get("type") == "text"):
                    return False
        return True
    return False

# --- Helper: Extract plain text from ADF comment body ---
def extract_text_from_adf(adf):
    if not adf or adf.get("type") != "doc":
        return ""
    result = []
    for block in adf.get("content", []):
        if block.get("type") == "paragraph":
            line = []
            for part in block.get("content", []):
                if part.get("type") == "text":
                    line.append(part.get("text", ""))
            result.append("".join(line))
    return "\n".join(result).strip()

# --- Helper: Get field format (plain string or adf) ---
def get_field_type(field_id):
    fields_url = f"{jira_url}/rest/api/3/field"
    response = requests.get(fields_url, auth=auth)
    response.raise_for_status()
    all_fields = response.json()
    for field in all_fields:
        if field.get("id") == field_id:
            schema = field.get("schema", {})
            field_type = schema.get("type", "")
            custom_type = schema.get("custom", "")
            if custom_type == "com.atlassian.jira.plugin.system.customfieldtypes:textarea":
                return "adf"
            return field_type  # e.g., "string"
    return ""

# --- Detect field type ---
field_type = get_field_type(custom_field_id)
if not field_type:
    print(f"Could not detect the type for field {custom_field_id}. Exiting.")
    exit(1)
print(f"\nDetected field type for {custom_field_id}: {field_type}")

# --- JQL search ---
search_url = f"{jira_url}/rest/api/3/search"
start_at = 0
max_results = 50
issues = []

print(f"\nFetching issues for project {project_key}...")
while True:
    params = {
        "jql": f"project = {project_key}",
        "startAt": start_at,
        "maxResults": max_results,
        "fields": f"summary,comment,{custom_field_id}"
    }
    response = requests.get(search_url, headers={"Accept": "application/json"}, auth=auth, params=params)
    response.raise_for_status()
    data = response.json()

    issues.extend(data["issues"])
    if start_at + max_results >= data["total"]:
        break
    start_at += max_results

print(f"Total issues retrieved: {len(issues)}")

# --- Update issues ---
update_url_template = f"{jira_url}/rest/api/3/issue/{{issue_key}}?notifyUsers=false"
headers = {
    "Accept": "application/json",
    "Content-Type": "application/json"
}

for issue in tqdm(issues, desc="Processing issues"):
    issue_key = issue["key"]
    issue_id = issue["id"]
    comments = issue["fields"].get("comment", {}).get("comments", [])
    custom_field_value = issue["fields"].get(custom_field_id)

    if not is_adf_field_empty(custom_field_value):
        result = "Skipped - Field already has a value"
    elif not comments:
        result = "Skipped - No comments"
    else:
        latest_comment = comments[-1]
        author = latest_comment["author"]["displayName"]
        body_adf = latest_comment["body"]
        body = extract_text_from_adf(body_adf)

        # Build payload based on field type
        if field_type == "string":
            update_payload = {
                "fields": {
                    custom_field_id: f"{author}: {body}"
                }
            }
        elif field_type == "adf":
            update_payload = {
                "fields": {
                    custom_field_id: {
                        "type": "doc",
                        "version": 1,
                        "content": [
                            {
                                "type": "paragraph",
                                "content": [
                                    {
                                        "type": "text",
                                        "text": f"{author}: {body}"
                                    }
                                ]
                            }
                        ]
                    }
                }
            }
        else:
            result = f"Skipped - Unhandled field type '{field_type}'"
            with open(log_file, "a", encoding="utf-8") as log:
                log.write(f"{issue_id} ({issue_key}): {result}\n")
            continue

        update_url = update_url_template.format(issue_key=issue_key)
        update_response = requests.put(update_url, headers=headers, auth=auth, json=update_payload)

        if update_response.status_code == 204:
            result = f"Updated - {issue_key}"
        else:
            result = f"Failed - {issue_key} - HTTP {update_response.status_code}: {update_response.text}"

    with open(log_file, "a", encoding="utf-8") as log:
        log.write(f"{issue_id} ({issue_key}): {result}\n")

print(f"\nProcessing complete. Log written to {log_file}")
