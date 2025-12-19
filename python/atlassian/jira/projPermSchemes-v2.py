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
    "Cloud_prod": config["Cloud_prod"]["url"],
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
    pat = config[instance_name].get("pat", None)
    password = config[instance_name].get("password", None)
except KeyError:
    print(f"Credentials not found for {instance_name}. Please update the config file.")
    exit(1)

# Define the base URL and endpoints
projects_endpoint = f"{jira_url}/rest/api/2/project"
permissionschemes_endpoint = f"{jira_url}/rest/api/2/permissionscheme"

# Attempt authentication using PAT first, fallback to password
auth = None
if pat:
    print("Attempting authentication using PAT...")
    auth = HTTPBasicAuth(username, pat)
    test_response = requests.get(projects_endpoint, auth=auth, verify=False)
    if test_response.status_code == 200:
        print("Authenticated successfully using PAT.")
    else:
        print("Failed to authenticate using PAT. Attempting password authentication.")
        auth = None

if not auth and password:
    print("Attempting authentication using password...")
    auth = HTTPBasicAuth(username, password)
    test_response = requests.get(projects_endpoint, auth=auth, verify=False)
    if test_response.status_code == 200:
        print("Authenticated successfully using password.")
    else:
        print("Failed to authenticate using both PAT and password. Exiting script.")
        exit(1)

# Fetch and write project and permission scheme data
print("Fetching project list...")
response = requests.get(projects_endpoint, auth=auth, verify=False)
if response.status_code == 200:
    projects = response.json()

    print("Fetching permission schemes...")
    permission_schemes = {}
    perm_schemes_response = requests.get(permissionschemes_endpoint, auth=auth, verify=False)
    if perm_schemes_response.status_code == 200:
        perm_schemes = perm_schemes_response.json().get('permissionSchemes', [])
        for scheme in perm_schemes:
            permission_schemes[scheme['id']] = scheme['name']
    else:
        print("Failed to retrieve permission schemes.")
        exit(1)

    # Write project and permission scheme information to a CSV file
    output_file = f"projPermSchems_{instance_name}.csv"
    with open(output_file, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["Project Key", "Project Name", "Permission Scheme Name"])
        print("Processing projects and writing to CSV...")
        for project in projects:
            project_key = project['key']
            project_name = project['name']
            permissions_endpoint = f"{jira_url}/rest/api/2/project/{project_key}/permissionscheme"

            # Get the project's permission scheme
            perm_response = requests.get(permissions_endpoint, auth=auth, verify=False)
            if perm_response.status_code == 200:
                perm_scheme = perm_response.json()
                perm_scheme_id = perm_scheme.get('id', None)
                perm_scheme_name = permission_schemes.get(perm_scheme_id, "Unknown Scheme")
                writer.writerow([project_key, project_name, perm_scheme_name])
                print(f"Processed project: {project_key} - {project_name}")
            else:
                print(f"Failed to get permission scheme for project {project_key}")

    print(f"Project and permission scheme information written to {output_file}")
else:
    print("Failed to retrieve projects.")
