import requests
import getpass
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Prompt user for credentials
username = input("Enter your username: ")
password = getpass.getpass("Enter your password: ")

# Define the base URL and endpoints for fetching projects and permission schemes
base_url = "https://sosjira.app.vumc.org/rest/api/2"
projects_endpoint = f"{base_url}/project"
permissionschemes_endpoint = f"{base_url}/permissionscheme"

# Make the request to get the list of projects
response = requests.get(projects_endpoint, auth=(username, password), verify=False)

# Check if the request was successful
if response.status_code == 200:
    projects = response.json()

    # Create a dictionary to store permission scheme names by ID
    permission_schemes = {}

    # Get all permission schemes
    perm_schemes_response = requests.get(permissionschemes_endpoint, auth=(username, password), verify=False)
    if perm_schemes_response.status_code == 200:
        perm_schemes = perm_schemes_response.json()['permissionSchemes']
        for scheme in perm_schemes:
            permission_schemes[scheme['id']] = scheme['name']

    # Create a file to write the project and permission scheme information
    with open("projPermSchems.txt", "w") as file:
        file.write("Project Key, Project Name, Permission Scheme Name\n")
        
        # Iterate through the projects to get their permission schemes
        for project in projects:
            project_key = project['key']
            project_name = project['name']
            
            # Define the endpoint to get project permissions
            permissions_endpoint = f"{base_url}/project/{project_key}/permissionscheme"
            
            # Make the request to get the permission scheme
            perm_response = requests.get(permissions_endpoint, auth=(username, password), verify=False)
            
            if perm_response.status_code == 200:
                perm_scheme = perm_response.json()
                perm_scheme_id = perm_scheme['id']
                perm_scheme_name = permission_schemes.get(perm_scheme_id, "Unknown Scheme")
                
                # Write the project and permission scheme information to the file
                file.write(f"{project_key}, {project_name}, {perm_scheme_name}\n")
            else:
                print(f"Failed to get permission scheme for project {project_key}")

    print("Project and permission scheme information written to projPermSchems.txt")
else:
    print("Failed to retrieve projects")
