import requests
from requests.auth import HTTPBasicAuth
import urllib3
import configparser
import os
import csv
import socket

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
    jira_url = instances[instance_name].rstrip('/')  # Ensure no trailing slash
except (IndexError, ValueError):
    print("Invalid choice. Exiting script.")
    exit(1)

# Validate that the hostname can be resolved
try:
    hostname = jira_url.split('/')[2]  # Extract the domain name from the URL
    print(f"Checking DNS resolution for: {hostname}")
    socket.gethostbyname(hostname)
    print("DNS resolution successful.")
except socket.gaierror:
    print(
        f"ERROR: Unable to resolve hostname {hostname}. Please check your network settings and ensure the Jira URL is correct.")
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


def handle_auth_failure(response):
    print(f"Authentication failed. Status Code: {response.status_code}")
    try:
        error_details = response.json()
        print("Error details:", error_details)
    except requests.exceptions.JSONDecodeError:
        print("No additional error details provided by Jira.")
    exit(1)


# Attempt PAT authentication first
if pat:
    print("Attempting authentication using PAT...")
    auth = HTTPBasicAuth(username, pat)
    test_url = f"{jira_url}/rest/api/2/project"
    print(f"Testing authentication with: {test_url}")
    try:
        test_response = requests.get(test_url, auth=auth, verify=False, timeout=10)
        if test_response.status_code == 200:
            print("Authenticated successfully using PAT.")
        else:
            handle_auth_failure(test_response)
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to Jira: {e}")
        auth = None

# If PAT authentication fails, attempt basic authentication
if not auth and password:
    print("Attempting authentication using username and password...")
    auth = HTTPBasicAuth(username, password)
    try:
        test_response = requests.get(test_url, auth=auth, verify=False, timeout=10)
        if test_response.status_code == 200:
            print("Authenticated successfully using username and password.")
        else:
            handle_auth_failure(test_response)
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to Jira: {e}")
        exit(1)


def verify_authentication():
    """
    Verifies that the authentication credentials are valid.
    """
    auth_urls = [
        f"{jira_url}/rest/api/3/myself",
        f"{jira_url}/rest/api/2/myself"
    ]

    for auth_url in auth_urls:
        print(f"Verifying authentication with: {auth_url}")
        try:
            response = requests.get(auth_url, auth=auth, verify=False, timeout=10)
            if response.status_code == 200:
                print(f"Authentication successful using {auth_url}.")
                return True
            elif response.status_code == 404:
                print(f"API endpoint not found: {auth_url}. Trying next version...")
            else:
                handle_auth_failure(response)
        except requests.exceptions.RequestException as e:
            print(f"Error connecting to Jira: {e}")

    print("ERROR: Authentication failed. Ensure your Jira instance supports either API v2 or v3.")
    return False


def extract_and_save():
    if not verify_authentication():
        print("Authentication failed. Exiting script.")
        return

    dashboards = fetch_dashboards()
    boards = fetch_boards()
    filters = fetch_filters()

    dashboard_data = [{
        "Name": d["name"],
        "Owner": d["owner"]["displayName"],
        "Shared With": ", ".join([s["name"] for s in d.get("sharePermissions", [])])
    } for d in dashboards]
    save_to_csv(dashboard_data, f"{instance_name}_dashboards.csv", ["Name", "Owner", "Shared With"])

    board_data = [{
        "Name": b["name"],
        "Owner": b.get("admin", {}).get("displayName", "Unknown"),
        "Shared With": "N/A"  # Jira Agile API doesn't directly provide share information
    } for b in boards]
    save_to_csv(board_data, f"{instance_name}_boards.csv", ["Name", "Owner", "Shared With"])

    filter_data = [{
        "Name": f["name"],
        "Owner": f["owner"]["displayName"],
        "Shared With": ", ".join([s["name"] for s in f.get("sharePermissions", [])])
    } for f in filters]
    save_to_csv(filter_data, f"{instance_name}_filters.csv", ["Name", "Owner", "Shared With"])


if __name__ == "__main__":
    extract_and_save()
