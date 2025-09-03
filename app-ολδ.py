import sys
from datetime import datetime
import logging

from flask import Flask, request, render_template, jsonify, send_file
from bs4 import BeautifulSoup
import requests
from urllib.parse import urljoin
from controller import Controller
import onetimescript
from db import db
import re
import uuid
from typing import Optional, Dict, Any
import json
import firebase_admin
from firebase_admin import credentials, messaging

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///domains.db'
db.init_app(app)

# APNs Configuration - REPLACE WITH YOUR ACTUAL VALUES
APNS_KEY_PATH = 'AuthKey_VM3QPGGY8L.p8'
TEAM_ID = 'JRXD7XLLMM'  # ← Replace this with your actual Team ID!
KEY_ID = 'VM3QPGGY8L'
BUNDLE_ID = 'com.malloc.phishingprotect'


cred = credentials.Certificate("malloc-sms-phishing-protect-firebase-adminsdk-fbsvc-841974cf1d.json")  # Downloaded from Firebase Console
firebase_admin.initialize_app(cred)

# Initialize APNs client


with app.app_context():
    db.create_all()

user_message_store = {}
device_tokens = {}  # Moved to global scope
controller = Controller()

logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

URL_REGEX = re.compile(
    r'(https?://[^\s]+)',
    re.IGNORECASE
)

@app.route("/send_silent_ios", methods=["POST"])
def send_silent_ios():
    """
    Endpoint to send a silent push notification to iOS devices.
    Expects JSON payload with:
    {
        "token": "<device_fcm_token>",
        "data": {"key1": "value1", "key2": "value2"}
    }
    """
    payload = request.get_json()
    token = payload.get("token")
    data = payload.get("data", {})

    if not token:
        return jsonify({"error": "Device token is required"}), 400

    # Ensure all data values are strings
    data = {k: str(v) for k, v in data.items()}

    # APNs config for silent notification
    apns_config = messaging.APNSConfig(
        headers={"apns-priority": "5"},
        payload=messaging.APNSPayload(
            aps=messaging.Aps(
                content_available=True
            )
        )
    )

    # Construct the message
    message = messaging.Message(
        token=token,
        data=data,
        apns=apns_config
    )

    try:
        response = messaging.send(message)
        return jsonify({"success": True, "response": response})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500




def send_silent_notification(token: str, data: dict):
    """
    Send silent push notification via Firebase Admin SDK
    """
    try:
        message = messaging.Message(
            notification=messaging.Notification(

            ),
            token=token,
            data=data or {}  # Optional custom data
        )

        response = messaging.send(message)
        return {"status": "success", "message_id": response}
    except Exception as e:
        return {"status": "error", "reason": str(e)}


def send_fcm_notification(token: str, title: str, body: str, data: dict = None):
    """
    Send push notification using Firebase Cloud Messaging
    """
    try:
        message = messaging.Message(
            notification=messaging.Notification(
                title=title,
                body=body
            ),
            token=token,
            data=data or {}  # Optional custom data
        )


        response = messaging.send(message)
        logger.info(f"Silent FCM sent successfully: {response}")
        return {"status": "success", "message_id": response}


    except Exception as e:
        logger.error(f"Error sending FCM notification: {str(e)}")
        return {"status": "error", "message": str(e)}




# Routes
@app.route('/apple-app-site-association', methods=['GET', 'POST'])
def serve_apple_app_site_association():
    return send_file('static/.well-known1/apple-app-site-association', mimetype='application/json')


@app.route('/.well-known/apple-app-site-association', methods=['GET', 'POST'])
def well_serve_apple_app_site_association():
    return send_file('static/.well-known1/apple-app-site-association', mimetype='application/json')


@app.route('/', methods=['GET', 'POST'])
def home():
    try:
        url = request.form['url']
        result = controller.main(url)
        output = result
    except:
        output = 'NA'
    return render_template('index.html', output=output)


@app.route('/registered-devices', methods=['GET'])
def get_registered_devices():
    return jsonify({
        "count": len(device_tokens),
        "devices": device_tokens
    }), 200


def send_security_alert_to_all_users(message, url: str = None, reason: str = None):
    if not device_tokens:
        logger.warning("No device tokens registered")
        return {"sent": 0, "failed": 0}

    results = {"sent": 0, "failed": 0}

    for device_token, device_info in device_tokens.items():
        try:
            result = send_fcm_notification(
                token=device_token,
                title="Security Alert 🚨",
                body=reason or "Suspicious activity detected",
                data={"message": json.dumps(message)}
            )

            if result["status"] == "success":
                results["sent"] += 1
            else:
                results["failed"] += 1

        except Exception as e:
            logger.error(f"Error sending alert: {str(e)}")
            results["failed"] += 1

    logger.info(f"Broadcast completed: {results['sent']} sent, {results['failed']} failed")
    return results


@app.route('/message-filter', methods=['POST'])
def message_filter():
    try:
        data = request.get_json()

        user_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
        sender = data.get('query', {}).get('sender', 'Unknown')
        body = data.get('query', {}).get('message', {}).get('text', '')
        # Ensure body is a string
        if not isinstance(body, str):
            body = str(body) if body is not None else ''


        logger.info(f"Incoming request from IP: {user_ip}, Sender: {sender}")

        urls = URL_REGEX.findall(body)
        if urls:
            result_data = controller.main(urls[0])
            is_suspicious = result_data.get('trust_score', 0) < 50
            reason = result_data.get('reason', 'Message from {sender} was filtered as suspicious.'.format(sender=sender))
        else:
            is_suspicious = False
            reason = "No URL found"

        # Store message
        stored_message = _store_message(user_ip, sender, body, is_suspicious, reason)


        message_data = {
            "id": stored_message.get('id', '12345'),  # Use stored message ID or default
            "ip":user_ip,
            "sender": sender,
            "body": f'{body}',
            "category": "security_alert",
            "date": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),  # Current UTC timestamp
            "reason": reason,
            "isSuspicious": is_suspicious
        }

        broadcast_results = send_security_alert_to_all_users(
            message=message_data,
            url=user_ip,
            reason=reason
        )

        logger.info(f"Broadcast results: {broadcast_results}")

        # Extract URLs for response
        urls = URL_REGEX.findall(body)
        if not urls:
            return jsonify({'filter': 'allow', 'reason': 'No URL found in message ' + user_ip}), 200

        url_to_check = urls[0]
        result_data = controller.main(url_to_check)
        trust_score = result_data.get('trust_score', 100)
        classification = 'filter' if trust_score < 50 else 'allow'

        response_payload = {
            'filter': classification,
            'trust_score': trust_score,
            'ip:': user_ip,
            'reason': result_data.get('reason', 'No specific reason provided.'),
            'url': url_to_check,
            'age': result_data.get('age'),
            'rank': result_data.get('rank'),
            'is_url_shortened': result_data.get('is_url_shortened'),
            'hsts_support': result_data.get('hsts_support'),
            'user_ip': user_ip,
            'notification_sent': is_suspicious and user_ip in device_tokens
        }

        return jsonify(response_payload), 200

    except Exception as e:
        return jsonify({'filter': 'allow', 'reason': f'Error: {str(e)}'}), 200


def _store_message(user_id, sender, body, is_suspicious, reason):
    message = {
        "id": str(uuid.uuid4()),
        "ip":user_id,
        "sender": sender,
        "body": body,
        "date": datetime.utcnow().isoformat(),
        "isSuspicious": is_suspicious,
        "reason": reason
    }

    if user_id not in user_message_store:
        user_message_store[user_id] = []
    user_message_store[user_id].append(message)
    user_message_store[user_id] = user_message_store[user_id][-50:]
    return message


@app.route('/get-filter-results', methods=['GET'])
def get_filter_results():
    user_ip = request.args.get('ip')
    if not user_ip:
        return jsonify({'error': 'IP missing'}), 400
    results = user_message_store.get(user_ip, [])
    return jsonify(results), 200


@app.route('/api/check-domain', methods=['POST'])
def check_domain_api():
    try:
        data = request.get_json()
        url = data.get('url')
        if not url:
            return jsonify({'error': 'Missing URL'}), 400
        result = controller.main(url)
        return jsonify({
            'status': result.get('status'),
            'trust_score': result.get('trust_score'),
            'reason': result.get('reason', 'No specific reason provided.'),
            'url': result.get('url'),
            'age': result.get('age'),
            'rank': result.get('rank'),
            'response_status': result.get('response_status'),
            'is_url_shortened': result.get('is_url_shortened'),
            'hsts_support': result.get('hsts_support'),
            'ssl': result.get('ssl'),
            'whois': result.get('whois'),
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/update-db')
def update_db():
    try:
        with app.app_context():
            response = onetimescript.update_db()
            print("Database populated successfully!")
            return response, 200
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return "An error occurred: " + str(e), 500


@app.route('/update-json')
def update_json():
    try:
        with app.app_context():
            response = onetimescript.update_json()
            print("JSON updated successfully!")
            return response, 200
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return "An error occurred: " + str(e), 500


@app.route('/test-push', methods=['POST'])
def test_push():
    try:
        data = request.get_json()
        device_token = data.get("deviceToken")
        custom_data = data.get("custom_data", {})

        if not device_token:
            return jsonify({"error": "Missing deviceToken"}), 400

        result = send_silent_notification(token=device_token, data=custom_data)

        if result["status"] == "success":
            return jsonify({"status": "Push sent successfully", "details": result}), 200
        else:
            return jsonify({"error": "Failed to send push", "details": result}), 500

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/save-sender', methods=['POST'])
def save_device_token():
    try:
        data = request.get_json()
        device_token = data.get('deviceToken')

        if not device_token:
            return jsonify({"error": "Missing deviceToken"}), 400

        # Save the device token as the key in the dictionary
        device_tokens[device_token] = {
            "deviceToken": device_token,
            "registered_at": datetime.utcnow().isoformat()
        }

        return jsonify({"status": "Device token saved successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.debug = True
    app.run()