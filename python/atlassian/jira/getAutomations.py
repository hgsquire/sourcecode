import requests
from requests.auth import HTTPBasicAuth
import urllib3
import configparser
import os
import csv
import logging

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration for logging
log_file = "jira_automation_info.log"
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

# Function to fetch automation rules
def fetch_automation_rules(endpoint, rule_type):
    response = requests.get(endpoint, auth=auth, verify=False)
    logging.debug(f"API response for {rule_type} rules: {response.status_code} - {response.text}")

    if response.status_code != 200:
        logging.error(f"Failed to retrieve {rule_type} rules: {response.status_code} - {response.text}")
        print(f"Error retrieving {rule_type} rules. Check logs for details.")
        return []

    rules = response.json().get("rules", [])
    return rules

# Function to write automation rules to a CSV file
def write_automation_to_csv(rules, csv_filename):
    csv_data = [("Automation Name", "Enabled", "Owner")]
    for rule in rules:
        name = rule.get("name", "Unknown")
        enabled = "Enabled" if rule.get("enabled", False) else "Disabled"
        owner = rule.get("creator", {}).get("displayName", "Unknown")
        csv_data.append((name, enabled, owner))

    with open(csv_filename, mode="w", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerows(csv_data)

    print(f"Automation data saved to '{csv_filename}'. Check '{log_file}' for API details.")

# Fetch global automation rules
print("\nFetching global automation rules...")
global_endpoint = f"{jira_url}/rest/automation/1.0/global/rules"
global_rules = fetch_automation_rules(global_endpoint, "global")

if global_rules:
    global_csv_filename = f"{instance_name}_global_automations.csv"
    write_automation_to_csv(global_rules, global_csv_filename)

# Fetch project-specific automation rules
project_key = input("\nEnter a project key to fetch project-specific automation rules: ").strip()
if project_key:
    print(f"\nFetching automation rules for project '{project_key}'...")
    project_endpoint = f"{jira_url}/rest/automation/1.0/project/{project_key}/rules"
    project_rules = fetch_automation_rules(project_endpoint, "project")

    if project_rules:
        project_csv_filename = f"{instance_name}_{project_key}_project_automations.csv"
        write_automation_to_csv(project_rules, project_csv_filename)
