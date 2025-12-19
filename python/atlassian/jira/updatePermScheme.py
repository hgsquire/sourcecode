import requests
from requests.auth import HTTPBasicAuth
import urllib3
import getpass

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Prompt for Jira credentials
username = input("Enter your Jira username: ")
password = getpass.getpass("Enter your Jira password: ")

# Jira API URL
base_url = 'https://sosjira.app.vumc.org/rest/api/2'

# Prompt for permission scheme name
permission_scheme_name = input("Enter the permission scheme name: ")

# Endpoint to fetch all permission schemes
schemes_url = f'{base_url}/permissionscheme'

# Headers
headers = {
    'Accept': 'application/json',
    'Content-Type': 'application/json'
}

# Fetch all permission schemes
response = requests.get(
    schemes_url,
    headers=headers,
    auth=HTTPBasicAuth(username, password),
    verify=False  # Suppress SSL verification
)

# Check if the request was successful
if response.status_code != 200:
    print(f"Failed to fetch permission schemes.")
    print(f"Response: {response.status_code} - {response.text}")
    exit(1)

# Parse the response JSON
permission_schemes = response.json()['permissionSchemes']

# Find the ID of the permission scheme with the given name
permission_scheme_id = None
for scheme in permission_schemes:
    if scheme['name'] == permission_scheme_name:
        permission_scheme_id = scheme['id']
        break

if permission_scheme_id is None:
    print(f"Permission scheme '{permission_scheme_name}' not found.")
    exit(1)

# Endpoint to fetch all projects
projects_url = f'{base_url}/project'

# Fetch all projects
response = requests.get(
    projects_url,
    headers=headers,
    auth=HTTPBasicAuth(username, password),
    verify=False  # Suppress SSL verification
)

# Check if the request was successful
if response.status_code != 200:
    print(f"Failed to fetch projects.")
    print(f"Response: {response.status_code} - {response.text}")
    exit(1)

# Parse the response JSON
projects = response.json()

# Iterate over each project and update its permission scheme
for project in projects:
    project_key = project['key']
    update_url = f'{base_url}/project/{project_key}/permissionscheme'
    data = {
        'id': permission_scheme_id
    }

    # Make the PUT request to update the permission scheme
    response = requests.put(
        update_url,
        headers=headers,
        json=data,
        auth=HTTPBasicAuth(username, password),
        verify=False  # Suppress SSL verification
    )

    # Check if the request was successful
    if response.status_code == 204:
        print(f"Successfully updated the permission scheme for project {project_key}.")
    elif response.status_code == 200:
        print(f"Permission scheme for project {project_key} is already set to the given permission scheme.")
    else:
        print(f"Failed to update the permission scheme for project {project_key}.")
        print(f"Response: {response.status_code} - {response.text}")
