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
    "ADI_Cloud_prod": config["ADI_Cloud_prod"]["url"],
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

# Set up authentication
auth = None

# Attempt PAT authentication first
if pat:
    print("Attempting authentication using PAT...")
    auth = HTTPBasicAuth(username, pat)
    test_url = f"{jira_url}/rest/api/2/project"
    test_response = requests.get(test_url, auth=auth, verify=False)
    if test_response.status_code == 200:
        print("Authenticated successfully using PAT.")
    else:
        print("Authentication failed using PAT.")
        auth = None

# If PAT authentication fails, attempt basic authentication
if not auth and password:
    print("Attempting authentication using username and password...")
    auth = HTTPBasicAuth(username, password)
    test_response = requests.get(test_url, auth=auth, verify=False)
    if test_response.status_code == 200:
        print("Authenticated successfully using username and password.")
    else:
        print("Authentication failed using username and password.")
        exit(1)

# Function: Fetch projects and write to CSV
def fetch_and_write_project_permission_data():
    """Fetch projects and their permission schemes, write to a CSV."""
    projects_endpoint = f"{jira_url}/rest/api/2/project"
    permissionschemes_endpoint = f"{jira_url}/rest/api/2/permissionscheme"

    print("Fetching project list...")
    response = requests.get(projects_endpoint, auth=auth, verify=False)
    if response.status_code != 200:
        print(f"Failed to fetch projects. Status Code: {response.status_code}")
        return

    projects = response.json()

    print("Fetching permission schemes...")
    response = requests.get(permissionschemes_endpoint, auth=auth, verify=False)
    if response.status_code != 200:
        print(f"Failed to fetch permission schemes. Status Code: {response.status_code}")
        return

    permission_schemes = {scheme['id']: scheme['name'] for scheme in response.json().get('permissionSchemes', [])}

    output_file = f"projPermSchems_{instance_name}.csv"
    with open(output_file, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["Project Key", "Project Name", "Permission Scheme Name"])
        for project in projects:
            project_key = project['key']
            project_name = project['name']
            permissions_endpoint = f"{jira_url}/rest/api/2/project/{project_key}/permissionscheme"
            response = requests.get(permissions_endpoint, auth=auth, verify=False)
            if response.status_code == 200:
                perm_scheme_id = response.json().get('id')
                perm_scheme_name = permission_schemes.get(perm_scheme_id, "Unknown Scheme")
                writer.writerow([project_key, project_name, perm_scheme_name])
    print(f"Project and permission scheme data written to {output_file}.")

# Function: Set permission schemes to read-only
def set_permission_scheme_to_read_only():
    """Set permission scheme for projects to a read-only scheme."""
    permission_scheme_name = input("Enter the new permission scheme name: ").strip()
    csv_file = input("Enter the CSV file with project names: ").strip()

    permissionschemes_endpoint = f"{jira_url}/rest/api/2/permissionscheme"
    print("Fetching permission schemes...")
    response = requests.get(permissionschemes_endpoint, auth=auth, verify=False)
    if response.status_code != 200:
        print(f"Failed to fetch permission schemes. Status Code: {response.status_code}")
        return

    permission_schemes = {scheme['name']: scheme['id'] for scheme in response.json().get('permissionSchemes', [])}
    permission_scheme_id = permission_schemes.get(permission_scheme_name)

    if not permission_scheme_id:
        print(f"Permission scheme '{permission_scheme_name}' not found.")
        return

    print("Processing projects...")
    with open(csv_file, mode="r", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        for row in reader:
            project_key = row['Project Key']
            update_url = f"{jira_url}/rest/api/2/project/{project_key}/permissionscheme"
            response = requests.put(update_url, auth=auth, json={"id": permission_scheme_id}, verify=False)
            if response.status_code == 204:
                print(f"Updated permission scheme for project {project_key}.")
            else:
                print(f"Failed to update permission scheme for project {project_key}. Status Code: {response.status_code}")

# Function: Reset projects to original permission scheme
def reset_projects_to_original_permission_scheme():
    """Reset projects to their original permission schemes."""
    csv_file = input("Enter the CSV file with project and permission scheme data: ").strip()

    print("Processing projects...")
    with open(csv_file, mode="r", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        for row in reader:
            project_key = row['Project Key']
            permission_scheme_name = row['Permission Scheme Name']
            permissionschemes_endpoint = f"{jira_url}/rest/api/2/permissionscheme"

            response = requests.get(permissionschemes_endpoint, auth=auth, verify=False)
            if response.status_code != 200:
                continue

            permission_schemes = {scheme['name']: scheme['id'] for scheme in response.json().get('permissionSchemes', [])}
            permission_scheme_id = permission_schemes.get(permission_scheme_name)

            if not permission_scheme_id:
                print(f"Permission scheme '{permission_scheme_name}' not found for project {project_key}.")
                continue

            update_url = f"{jira_url}/rest/api/2/project/{project_key}/permissionscheme"
            response = requests.put(update_url, auth=auth, json={"id": permission_scheme_id}, verify=False)
            if response.status_code == 204:
                print(f"Reset permission scheme for project {project_key}.")
            else:
                print(f"Failed to reset permission scheme for project {project_key}. Status Code: {response.status_code}")

# Main function
def main():
    """Main function to run the script."""
    print("Select an option:")
    print("1. Create a CSV file with existing project schemes.")
    print("2. Set permission schemes to a read-only scheme.")
    print("3. Reset projects to their original permission scheme.")
    print("4. Exit.")
    choice = input("Enter your choice (1/2/3/4): ").strip()

    if choice == "1":
        fetch_and_write_project_permission_data()
    elif choice == "2":
        set_permission_scheme_to_read_only()
    elif choice == "3":
        reset_projects_to_original_permission_scheme()
    elif choice == "4":
        print("Exiting script.")
        exit(0)
    else:
        print("Invalid choice. Exiting script.")

if __name__ == "__main__":
    main()
