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
    "HIT_Cloud_prod": config["HIT_Cloud_prod"]["url"],
    "ADI_Cloud_prod": config["ADI_Cloud_prod"]["url"],
    "HIT_sandbox": config["HIT_sandbox"]["url"],
    "ADI_sandbox": config["ADI_sandbox"]["url"],
    "VEC_sandbox": config["VEC_sandbox"]["url"],
}

# Prompt user to select an instance
print("Available Jira Cloud instances:")
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
except KeyError:
    print(f"Credentials not found for {instance_name}. Please update the config file.")
    exit(1)

# Set up authentication
def authenticate():
    auth = HTTPBasicAuth(username, pat)
    test_url = f"{jira_url}/rest/api/3/myself"
    response = requests.get(test_url, auth=auth, verify=False)
    if response.status_code == 200:
        print("Authentication successful.")
        return auth
    else:
        print("Authentication failed.")
        exit(1)

auth = authenticate()

# Fetch all filters
def get_all_filters():
    url = f"{jira_url}/rest/api/3/filter/search"
    filters = []
    start_at = 0
    max_results = 50  # Jira API paginates results

    while True:
        params = {
            "startAt": start_at,
            "maxResults": max_results,
            "overrideSharePermissions": "true"  # Experimental parameter to retrieve all filters
        }
        response = requests.get(url, auth=auth, params=params, verify=False)
        if response.status_code == 200:
            data = response.json()
            filters.extend(data.get("values", []))
            if data.get("isLast", True):
                break
            start_at += max_results
        else:
            print(f"Failed to fetch filters: {response.status_code} {response.text}")
            break

    return filters

# Write filters to CSV
def write_filters_to_csv(filters):
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"jira_filters_{instance_name}_{timestamp}.csv"
    with open(filename, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(["Filter Name", "Filter ID", "Owner"])
        for filter in filters:
            writer.writerow([filter.get("name"), filter.get("id"), filter.get("owner", {}).get("displayName", "Unknown")])
    print(f"Filters exported to {filename}")

if __name__ == "__main__":
    filters = get_all_filters()
    if filters:
        write_filters_to_csv(filters)
    else:
        print("No filters found.")
