import requests
from requests.auth import HTTPBasicAuth
import urllib3
import configparser
import os
import csv
from datetime import datetime
import logging

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration for logging
log_file = "jira_project_info.log"
logging.basicConfig(filename=log_file, level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

# Configuration file for URLs and credentials
config_file = "jira_config.ini"

if not os.path.exists(config_file):
    logging.error(f"Configuration file '{config_file}' not found. Exiting script.")
    exit(1)

config = configparser.ConfigParser()
config.read(config_file)

instances = {key: config[key]["url"] for key in config.keys() if key != "DEFAULT"}

print("Available Jira instances:")
for i, instance in enumerate(instances.keys(), 1):
    print(f"{i}. {instance}")
choice = input("Select an instance by number: ").strip()

try:
    instance_name = list(instances.keys())[int(choice) - 1]
    jira_url = instances[instance_name]
except (IndexError, ValueError):
    logging.error("Invalid choice for instance. Exiting script.")
    exit(1)

# Load credentials for the chosen instance
try:
    username = config[instance_name]["username"]
    pat = config[instance_name].get("pat")
    password = config[instance_name].get("password")
except KeyError as e:
    logging.error(f"Missing required credential for {instance_name}: {e}. Please update the config file.")
    exit(1)

# Function to test authentication
def test_auth(auth):
    auth_test_url = f"{jira_url}/rest/api/2/myself"
    response = requests.get(auth_test_url, auth=auth, verify=False)
    if response.status_code == 200:
        logging.info("Authentication successful.")
        return True
    logging.warning(f"Authentication failed: {response.status_code} - {response.text}")
    return False

# Attempt authentication using pat, then fallback to password
auth = None
if pat:
    logging.info("Attempting authentication using Personal Access Token (PAT).")
    auth = HTTPBasicAuth(username, pat)
    if not test_auth(auth):
        logging.info("PAT authentication failed. Attempting authentication using password.")
        auth = None

if not auth and password:
    auth = HTTPBasicAuth(username, password)
    if not test_auth(auth):
        logging.error("Password authentication failed. Exiting script.")
        print("Authentication failed. Check credentials in the configuration file.")
        exit(1)

if not auth:
    logging.error("No valid authentication method found. Exiting script.")
    exit(1)

# Helper functions
def get_project_details(project_key):
    search_url = f"{jira_url}/rest/api/2/search"
    query = {"jql": f"project={project_key}", "maxResults": 1, "fields": "updated"}
    response = requests.get(search_url, auth=auth, params=query, verify=False)
    logging.debug(f"API response for project search ({project_key}): {response.status_code} - {response.text}")

    if response.status_code == 200:
        data = response.json()
        total_issues = data.get("total", 0)
        last_updated = data["issues"][0]["fields"]["updated"] if total_issues > 0 else "N/A"
        return total_issues, last_updated
    else:
        return "Error", "Error"

def get_project_lead(project):
    lead = project.get("lead", {})
    display_name = lead.get("displayName", "Unknown")
    logging.debug(f"Extracted lead info for project {project.get('key')}: {lead}")
    return display_name

# Get project data using expand=lead
projects_url = f"{jira_url}/rest/api/2/project?expand=lead"
response = requests.get(projects_url, auth=auth, verify=False)

logging.debug(f"API response for listing projects: {response.status_code} - {response.text}")

if response.status_code != 200:
    logging.error(f"Failed to retrieve projects: {response.status_code} - {response.text}")
    print(f"Error retrieving projects. Check logs for details.")
    exit(1)

projects = response.json()
csv_data = [("Project Name", "Key", "Project ID", "Lead", "Last Update", "Number of Issues")]

for project in projects:
    logging.debug(f"Project raw data: {project}")
    project_name = project.get("name", "Unknown")
    project_key = project.get("key", "Unknown")
    project_id = project.get("id", "Unknown")  # Added project ID
    project_lead = get_project_lead(project)
    total_issues, last_updated = get_project_details(project_key)
    csv_data.append((project_name, project_key, project_id, project_lead, last_updated, total_issues))

csv_filename = f"{instance_name}_projects_detailed.csv"
with open(csv_filename, mode="w", newline="", encoding="utf-8") as csv_file:
    writer = csv.writer(csv_file)
    writer.writerows(csv_data)

print(f"Project data saved to '{csv_filename}'. Check '{log_file}' for API details.")
