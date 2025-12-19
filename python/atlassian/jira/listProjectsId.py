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


# Function to authenticate with fallback
def authenticate_with_fallback(url):
    if pat:
        print("Attempting authentication with PAT...")
        auth = HTTPBasicAuth(username, pat)
        response = requests.get(f"{url}/rest/api/2/myself", auth=auth, verify=False)
        if response.status_code == 200:
            print("Authentication with PAT succeeded.")
            return auth
        else:
            print("Authentication with PAT failed.")

    if password:
        print("Attempting authentication with username and password...")
        auth = HTTPBasicAuth(username, password)
        response = requests.get(f"{url}/rest/api/2/myself", auth=auth, verify=False)
        if response.status_code == 200:
            print("Authentication with username and password succeeded.")
            return auth
        else:
            print("Authentication with username and password failed.")

    print("Authentication failed for all methods. Exiting.")
    exit(1)


# Function to save users to CSV
def save_users_to_csv(url, auth, filename):
    try:
        # Retrieve all groups
        group_response = requests.get(
            f"{url}/rest/api/2/groups/picker",
            auth=auth,
            verify=False
        )
        if group_response.status_code != 200:
            print(f"Failed to retrieve groups. Status code: {group_response.status_code}")
            print(f"Response: {group_response.text}")
            return

        groups = group_response.json().get("groups", [])
        if not groups:
            print("No groups found in the Jira instance.")
            return

        # Prepare CSV data
        csv_data = [("Display Name", "User Name", "Email Address", "Jira ID")]
        user_ids = set()  # To avoid duplicates

        # Iterate over each group
        for group in groups:
            group_name = group["name"]
            start_at = 0
            while True:
                # Get group members with pagination
                user_response = requests.get(
                    f"{url}/rest/api/2/group/member",
                    params={"groupname": group_name, "startAt": start_at, "maxResults": 50},
                    auth=auth,
                    verify=False
                )
                if user_response.status_code != 200:
                    print(
                        f"Failed to retrieve users for group '{group_name}'. Status code: {user_response.status_code}")
                    print(f"Response: {user_response.text}")
                    break

                users = user_response.json().get("values", [])
                if not users:
                    break

                for user in users:
                    # Use 'name' for username and 'key' for Jira ID
                    user_name = user.get("name", "N/A")
                    user_key = user.get("key", "N/A")  # Jira ID in format "JIRAUSER106062"
                    if user_name not in user_ids:
                        user_ids.add(user_name)
                        csv_data.append((
                            user.get("displayName", "N/A"),
                            user_name,
                            user.get("emailAddress", "N/A"),
                            user_key
                        ))

                start_at += len(users)

        # Write users to CSV
        with open(filename, mode='w', newline='', encoding='utf-8') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerows(csv_data)

        print(f"User details have been saved to '{filename}'.")
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to Jira instance: {e}")


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

# Authenticate
auth = authenticate_with_fallback(jira_url)

# Save user details to CSV
user_csv_filename = f"{instance_name}_users.csv"
save_users_to_csv(jira_url, auth, user_csv_filename)
