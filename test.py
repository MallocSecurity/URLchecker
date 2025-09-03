import json
import requests
from google.oauth2 import service_account
import google.auth.transport.requests

# Path to your Firebase service account JSON file
SERVICE_ACCOUNT_FILE = "malloc-sms-phishing-protect-firebase-adminsdk-fbsvc-841974cf1d.json"
# Your Firebase project ID
PROJECT_ID = "malloc-sms-phishing-protect"
# Your device FCM registration token
DEVICE_TOKEN = "dU_nyBBRWUSkmuzxBskYYk:APA91bG1YXcuLdM0vLjf4ud1QYb8qeqx4ItC_Pd0Obyn1C5TGU0vWnlLuDnLiW-FCIQBWXx9c4E5Bpk1asgTVFy4BVYIVg1zBiaEk0sIRfy7m1pkgfwB9_g"

# ----------------------------------------------------------------------------
# Auth → Get OAuth2 access token
# ----------------------------------------------------------------------------
SCOPES = ["https://www.googleapis.com/auth/firebase.messaging"]
credentials = service_account.Credentials.from_service_account_file(
    SERVICE_ACCOUNT_FILE, scopes=SCOPES
)
auth_req = google.auth.transport.requests.Request()
credentials.refresh(auth_req)
access_token = credentials.token

# ----------------------------------------------------------------------------
# Silent push payload
# ----------------------------------------------------------------------------
message_payload = {
    "message": {
        "token": DEVICE_TOKEN,
        "apns": {
            "headers": {
                "apns-priority": "5"  # low priority, silent push
            },
            "payload": {
                "aps": {
                    "content-available": 1,  # required for silent push
                    "sound": ""  # required for silent push
                }
            }
        },
        "android": {
            "priority": "high",
            "data": {
                "action": "verify_ip",
                "event_id": "1",
                "ip": "46.199.91.178",
                "date": "2025-09-02T16:04:32Z"
            }
        },
        "data": {  # iOS and generic custom data
            "action": "verify_ip",
            "event_id": "1",
            "ip": "46.199.91.178",
            "date": "2025-09-02T16:04:32Z"
        }
    }
}

# ----------------------------------------------------------------------------
# Send request
# ----------------------------------------------------------------------------
url = f"https://fcm.googleapis.com/v1/projects/{PROJECT_ID}/messages:send"
headers = {
    "Authorization": f"Bearer {access_token}",
    "Content-Type": "application/json; UTF-8",
}

response = requests.post(url, headers=headers, json=message_payload)

print("Status Code:", response.status_code)
print("Response:", response.text)
