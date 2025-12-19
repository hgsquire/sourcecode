import requests
import json

# Configuration
API_TOKEN = "ATATT3xFfGF0KKqaGXawy8ayFpuMwNcqyfBXD6e4ctZrgYon5U7QHgZgZWFoO2XVHtVTU5OEKy545ydG9FWjH3Pm5ZM16KWPFEVyjKetqyn-hkPHUugXsd1swTJJGyi2X7dAT3TfT3FAGb_8AAF98omW4zxl77etaXL1Abz9ptYm66X1C9umPXw=E9BDE23F"
ORG_ID = "40c2ka3b-c45b-1128-68bk-8a70998277a7"  # Replace with your organization's ID
BASE_URL = "https://api.atlassian.com/admin/v1/users"

# Headers for authentication
HEADERS = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Content-Type": "application/json"
}


def get_user_account_id(user_id):
    """Fetches the user's account ID by their user ID."""
    try:
        response = requests.get(BASE_URL, headers=HEADERS)
        response.raise_for_status()
        users = response.json()

        for user in users.get("values", []):
            if user.get("accountId") == user_id:
                return user

        print("User not found.")
        return None
    except requests.exceptions.RequestException as e:
        print(f"Error fetching user details: {e}")
        return None


def update_user_email(account_id, new_email):
    """Updates the email address for the specified user."""
    url = f"{BASE_URL}/{account_id}/manage/email"
    payload = {
        "email": new_email
    }

    try:
        response = requests.post(url, headers=HEADERS, data=json.dumps(payload))
        response.raise_for_status()
        print("Email address updated successfully.")
    except requests.exceptions.RequestException as e:
        print(f"Error updating email address: {e}")


if __name__ == "__main__":
    # Input user ID and new email
    user_id = input("Enter the user's account ID: ").strip()
    new_email = input("Enter the new email address: ").strip()

    # Fetch user details
    user_details = get_user_account_id(user_id)

    if user_details:
        print(f"User found: {user_details['displayName']} ({user_details['email']})")

        # Update email address
        update_user_email(user_id, new_email)
