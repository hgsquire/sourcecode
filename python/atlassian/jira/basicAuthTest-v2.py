import requests
from requests.auth import HTTPBasicAuth
import urllib3
import configparser
import os
import csv

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration file for URLs and credentials
config_file = "jira_config.ini"

# Check if the configuration file exists
if not os.path.exists(config_file):
    print(f"Configuration file '{config_file}' not found. Please create one.")
    exit(1)

# Read configuration
config = configparser.ConfigParser()
config.read(config_file)

# Define Jira instances
instances = {
    "HIT_prod": config["HIT_prod"]["url"],
    "HIT_test": config["HIT_test"]["url"],
    "ADI_prod": config["ADI_prod"]["url"],
    "ADI_test": config["ADI_test"]["url"],
    "VEC_prod": config["VEC_prod"]["url"],
    "VEC_test": config["VEC_test"]["url"],
    "HIT_Cloud_prod": config["HIT_Cloud_prod"]["url"],
    "HIT_sandbox": config["HIT_sandbox"]["url"],
    "ADI_sandbox": config["ADI_sandbox"]["url"],
    "VEC_sandbox": config["VEC_sandbox"]["url"],
}

# Prompt user to select an instance
print("Available Jira instances:")
for i, instance in enumerate(instances.keys(), 1):
    print(f"{i}. {instance}")
choice = input("Select an instance by number: ").strip()

try:
    instance_name = list(instances.keys())[int(choice) - 1]
    jira_url = instances[instance_name]
except (IndexError, ValueError):
    print("Invalid choice. Exiting script.")
    exit(1)

# Load credentials for the chosen instance
try:
    username = config[instance_name]["username"]
    pat = config[instance_name]["pat"]
except KeyError:
    print(f"Credentials not found for {instance_name}. Please update the config file.")
    exit(1)

# Basic authentication setup
auth = HTTPBasicAuth(username, pat)

# Basic API call to list projects
try:
    response = requests.get(f"{jira_url}/rest/api/2/project", auth=auth, verify=False)
    print(f"Status Code: {response.status_code}")
    if response.status_code == 200:
        projects = response.json()
        print("List of Jira projects:")

        # Prepare data for CSV
        csv_data = [("Project Name", "Key")]
        for project in projects:
            print(f"- {project['name']} ({project['key']})")
            csv_data.append((project['name'], project['key']))

        # Create CSV file
        csv_filename = f"{instance_name}_projects.csv"
        with open(csv_filename, mode='w', newline='', encoding='utf-8') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerows(csv_data)

        print(f"\nProject details have been saved to '{csv_filename}'.")
    else:
        print(f"Failed to retrieve projects. Status code: {response.status_code}")
        print(f"Response: {response.text}")
except requests.exceptions.RequestException as e:
    print(f"Error connecting to Jira instance: {e}")
