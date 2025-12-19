import requests
from requests.auth import HTTPBasicAuth
import urllib3
import configparser
import os

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
    test_url = f"{jira_url}/rest/api/2/project"

    if pat:
        print("Attempting authentication using PAT...")
        auth = HTTPBasicAuth(username, pat)
        test_response = requests.get(test_url, auth=auth, verify=False)
        if test_response.status_code == 200:
            print("Authenticated successfully using PAT.")
        else:
            print("Authentication failed using PAT.")
            auth = None

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


# Get all projects
def get_all_projects():
    url = f"{jira_url}/rest/api/2/project"
    response = requests.get(url, auth=auth, verify=False)

    if response.status_code == 200:
        return response.json()
    else:
        print("Failed to retrieve projects.")
        return []


# Get the role ID for "Administrator"
def get_admin_role_id():
    url = f"{jira_url}/rest/api/2/role"
    response = requests.get(url, auth=auth, verify=False)

    if response.status_code == 200:
        roles = response.json()
        for role in roles:
            if role["name"].lower() == "administrators":
                return role["id"]
    print("Administrator role not found.")
    return None


# Add user to Administrator role in a specific project
def modify_user_role_in_project(project_key, username_to_modify, action):
    role_id = get_admin_role_id()
    if not role_id:
        print("Could not retrieve admin role.")
        return

    url = f"{jira_url}/rest/api/2/project/{project_key}/role/{role_id}"
    payload = {"user": [username_to_modify]}

    if action == "add":
        response = requests.post(url, auth=auth, json=payload, verify=False)
        success_code = 201
        action_text = "added"
    else:
        response = requests.delete(url, auth=auth, json=payload, verify=False)
        success_code = 204
        action_text = "removed"

    if response.status_code == success_code:
        print(f"Successfully {action_text} {username_to_modify} in {project_key}.")
    else:
        print(f"Failed to {action_text} {username_to_modify} in {project_key}. Response: {response.text}")


# Add user to Administrator role in all projects
def add_user_to_admin_role(username_to_add):
    projects = get_all_projects()
    for project in projects:
        modify_user_role_in_project(project["key"], username_to_add, "add")


# Remove user from Administrator role in all projects
def remove_user_from_admin_role(username_to_remove):
    projects = get_all_projects()
    for project in projects:
        modify_user_role_in_project(project["key"], username_to_remove, "remove")


# Prompt user for action
print("\nChoose an action:")
print("1. Add a user to Administrator role in all projects")
print("2. Remove a user from Administrator role in all projects")
print("3. Add/Remove a user to/from a single project")
action_choice = input("Select an action by number: ").strip()

if action_choice == "1":
    user_to_add = input("Enter the username to add: ").strip()
    add_user_to_admin_role(user_to_add)
elif action_choice == "2":
    user_to_remove = input("Enter the username to remove: ").strip()
    remove_user_from_admin_role(user_to_remove)
elif action_choice == "3":
    project_key = input("Enter the project key: ").strip()
    print("Choose an action for the single project:")
    print("1. Add user to Administrator role")
    print("2. Remove user from Administrator role")
    sub_choice = input("Enter choice (1 or 2): ").strip()

    if sub_choice == "1":
        user_to_add = input("Enter the username to add: ").strip()
        modify_user_role_in_project(project_key, user_to_add, "add")
    elif sub_choice == "2":
        user_to_remove = input("Enter the username to remove: ").strip()
        modify_user_role_in_project(project_key, user_to_remove, "remove")
    else:
        print("Invalid choice for single project action.")
else:
    print("Invalid choice. Exiting script.")
