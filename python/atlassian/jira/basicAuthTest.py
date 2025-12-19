import requests
from requests.auth import HTTPBasicAuth
import urllib3
import getpass

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Hardcoded Jira URLs for dev and prod instances
jira_url_dev = "https://vec-sandbox-instance.atlassian.net/rest/api/2/project"
jira_url_prod = "https://jira.app.vumc.org/rest/api/2/project"

# Prompt to choose the environment
env_choice = input("Choose the Jira environment (dev/prod): ").strip().lower()

# Set the Jira URL based on the user's choice
if env_choice == "dev":
    jira_url = jira_url_dev
elif env_choice == "prod":
    jira_url = jira_url_prod
else:
    print("Invalid choice. Exiting script.")
    exit(1)

# Prompt for Jira username and password (password will be hidden)
username = input("Enter your Jira username: ")
password = getpass.getpass("Enter your Jira password: ")

# Perform basic authentication
auth = HTTPBasicAuth(username, password)

# Make the request to the Jira API
response = requests.get(jira_url, auth=auth, verify=False)

# Check if the request was successful
print(f"Status Code: {response.status_code}")
if response.status_code == 200:
    try:
        projects = response.json()
        print("List of Jira projects:")
        for project in projects:
            print(f"- {project['name']}")
    except requests.exceptions.JSONDecodeError:
        print("Error: Unable to decode the JSON response.")
        print("Raw Response Text:", response.text)
else:
    print(f"Failed to retrieve projects. Status code: {response.status_code}")
    print(f"Response: {response.text}")