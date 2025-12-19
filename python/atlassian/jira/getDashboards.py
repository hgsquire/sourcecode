import requests
from requests.auth import HTTPBasicAuth
import urllib3
import configparser
import os
import csv
import datetime

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

    # Attempt PAT authentication first
    if pat:
        print("Attempting authentication using PAT...")
        auth = HTTPBasicAuth(username, pat)
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


def fetch_all_dashboards():
    dashboards = []
    start_at = 0
    max_results = 50  # Increase pagination size

    if "Cloud" in instance_name:
        max_results = 100  # Jira Cloud supports larger result sets

    while True:
        url = f"{jira_url}/rest/api/3/dashboard/search?startAt={start_at}&maxResults={max_results}" if "Cloud" in instance_name else f"{jira_url}/rest/api/2/dashboard?expand=owner&startAt={start_at}&maxResults={max_results}"
        response = requests.get(url, auth=auth, verify=False)

        if response.status_code != 200:
            print(f"Failed to retrieve dashboards. Status Code: {response.status_code}")
            return []

        data = response.json()
        dashboards.extend(data.get("values", []) if "Cloud" in instance_name else data.get("dashboards", []))

        if len(data.get("values", [])) < max_results if "Cloud" in instance_name else len(
                data.get("dashboards", [])) < max_results:
            break  # No more dashboards to fetch

        start_at += max_results

    return dashboards


def process_dashboards(dashboards):
    dashboard_data = []
    for dashboard in dashboards:
        dashboard_id = dashboard.get("id", "Unknown")
        name = dashboard.get("name", "Unknown")
        owner = dashboard.get("owner", {}).get("displayName",
                                               "Unknown") if "Cloud" not in instance_name else dashboard.get("owner",
                                                                                                             {}).get(
            "accountId", "Unknown")
        dashboard_data.append([dashboard_id, name, owner])

    return dashboard_data


def write_to_csv(dashboard_data):
    filename = f"jira_dashboards_{instance_name}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

    with open(filename, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["Dashboard ID", "Name", "Owner"])
        writer.writerows(dashboard_data)

    print(f"Dashboard data successfully written to {filename}")


def main():
    dashboards = fetch_all_dashboards()
    if not dashboards:
        print("No dashboards found or failed to retrieve data.")
        return

    dashboard_data = process_dashboards(dashboards)
    write_to_csv(dashboard_data)


if __name__ == "__main__":
    main()
