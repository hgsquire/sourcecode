import requests
from requests.auth import HTTPBasicAuth
import urllib3
import configparser
import os
import json

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
def authenticate():
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

    return auth

auth = authenticate()

# Fetch all permission schemes
def get_permission_schemes(jira_url, auth):
    url = f"{jira_url}/rest/api/2/permissionscheme"
    response = requests.get(url, auth=auth, verify=False)
    if response.status_code == 200:
        return response.json().get("permissionSchemes", [])
    else:
        print("Failed to retrieve permission schemes.")
        print(response.text)
        exit(1)

# Fetch detailed permission scheme information with expanded details
def get_permission_scheme_details(jira_url, auth, scheme_id):
    url = f"{jira_url}/rest/api/2/permissionscheme/{scheme_id}?expand=permissions,user,group,projectRole,field,all"
    response = requests.get(url, auth=auth, verify=False)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to retrieve details for scheme ID {scheme_id}.")
        print(response.text)
        return None

# Check if a permission scheme name exists in the target instance
def check_existing_schemes(jira_url, auth, scheme_name):
    existing_schemes = get_permission_schemes(jira_url, auth)
    for scheme in existing_schemes:
        if scheme['name'] == scheme_name:
            return True
    return False

# Export permission schemes with details
def export_permission_schemes(schemes, selected_indices):
    detailed_schemes = []
    for i in selected_indices:
        scheme_id = schemes[i]['id']
        details = get_permission_scheme_details(jira_url, auth, scheme_id)
        if details:
            detailed_schemes.append(details)
    with open("permission_schemes_export.json", "w") as file:
        json.dump(detailed_schemes, file, indent=4)
    print("Permission schemes with details exported successfully.")

# Import permission schemes from a JSON file and configure actions for groups, roles, and users
def import_permission_schemes(jira_url, auth):
    if not os.path.exists("permission_schemes_export.json"):
        print("Export file not found. Please export schemes first.")
        return

    with open("permission_schemes_export.json", "r") as file:
        schemes = json.load(file)

    for scheme in schemes:
        original_name = scheme["name"]
        permissions = scheme.get("permissions", [])
        formatted_permissions = []

        # Transform permissions to Jira Cloud's expected format
        for permission in permissions:
            holder = permission.get("holder", {})
            formatted_permission = {
                "permission": permission.get("permission"),
                "holder": {}
            }

            # Map holder types
            if holder.get("type") == "group":
                formatted_permission["holder"] = {
                    "type": "group",
                    "parameter": holder.get("parameter")
                }
            elif holder.get("type") == "user":
                formatted_permission["holder"] = {
                    "type": "user",
                    "parameter": holder.get("parameter")
                }
            elif holder.get("type") == "projectRole":
                formatted_permission["holder"] = {
                    "type": "projectRole",
                    "parameter": holder.get("parameter")
                }

            formatted_permissions.append(formatted_permission)

        # Prepare the payload for import
        scheme_payload = {
            "name": scheme["name"],
            "description": scheme.get("description", ""),
            "permissions": formatted_permissions
        }

        # Check if the scheme already exists and adjust the name if necessary
        while check_existing_schemes(jira_url, auth, scheme_payload["name"]):
            scheme_payload["name"] += " - Imported"

        # Import the permission scheme
        url = f"{jira_url}/rest/api/2/permissionscheme"
        response = requests.post(url, auth=auth, json=scheme_payload, verify=False)
        if response.status_code in (200, 201):
            print(f"Imported scheme: {scheme_payload['name']}")
        else:
            print(f"Failed to import scheme: {original_name}")
            print(response.text)

# Main menu
def main():
    schemes = get_permission_schemes(jira_url, auth)

    print("Available permission schemes:")
    for i, scheme in enumerate(schemes):
        print(f"{i + 1}. {scheme['name']}")

    action = input("Choose an action: 1) Export, 2) Import: ").strip()

    if action == "1":
        print("Enter the numbers of the schemes to export (comma-separated), or 'all' for all schemes.")
        selection = input("Your choice: ").strip()

        if selection.lower() == "all":
            export_permission_schemes(schemes, list(range(len(schemes))))
        else:
            indices = [int(i) - 1 for i in selection.split(",")]
            export_permission_schemes(schemes, indices)

    elif action == "2":
        import_permission_schemes(jira_url, auth)
    else:
        print("Invalid action. Exiting.")

if __name__ == "__main__":
    main()
