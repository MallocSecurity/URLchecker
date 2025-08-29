import sys
from datetime import datetime
import logging
from apns2.client import APNsClient, NotificationPriority
from apns2.credentials import TokenCredentials
from apns2.payload import Payload
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

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///domains.db'
db.init_app(app)

# APNs Configuration - REPLACE WITH YOUR ACTUAL VALUES
APNS_KEY_PATH = 'AuthKey_VM3QPGGY8L.p8'
TEAM_ID = 'JRXD7XLLMM'  # ← Replace this with your actual Team ID!
KEY_ID = 'VM3QPGGY8L'
BUNDLE_ID = 'com.malloc.phishingprotect'

# Initialize APNs client
apns_client = APNsClient(
    credentials=TokenCredentials(
        auth_key_path=APNS_KEY_PATH,
        auth_key_id=KEY_ID,
        team_id=TEAM_ID
    ),
    use_sandbox=True  # Set to True for development/testing
)

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


def send_apns_notification(token_hex: str, notification: Payload, topic: Optional[str] = None,
                           priority: NotificationPriority = NotificationPriority.Immediate,
                           expiration: Optional[int] = None, collapse_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Send a synchronous push notification using your existing APNs client
    """
    try:
        stream_id = apns_client.send_notification_async(
            token_hex, notification, topic, priority, expiration, collapse_id
        )
        result = apns_client.get_notification_result(stream_id)

        if result == 'Success':
            logger.info(f"Notification sent successfully to token: {token_hex}")
            return {"status": "success", "message": "Notification delivered"}
        else:
            from apns2.errors import exception_class_for_reason
            error_msg = f"APNs error: {result}"
            logger.error(f"Failed to send notification to {token_hex}: {error_msg}")
            return {"status": "error", "reason": result, "message": str(error_msg)}

    except Exception as e:
        logger.error(f"Exception sending notification to {token_hex}: {str(e)}")
        return {"status": "error", "reason": "Exception", "message": str(e)}


def send_security_alert(user_ip: str, message: str, url: str = None, reason: str = None):
    """
    Send security alert push notification to a user
    """
    if user_ip not in device_tokens:
        logger.warning(f"No device token found for user_ip: {user_ip}")
        return False

    device_info = device_tokens[user_ip]
    device_token = device_info['deviceToken']
    app_bundle_id = device_info.get('app_bundle_id', BUNDLE_ID)

    custom_data = {
        "type": "security_alert",
        "timestamp": datetime.utcnow().isoformat(),
        "user_ip": user_ip
    }

    if url:
        custom_data["url"] = url
    if reason:
        custom_data["reason"] = reason

    try:
        payload = Payload(
            alert=message,
            badge=1,
            sound="default",
            custom=custom_data
        )

        result = send_apns_notification(
            token_hex=device_token,
            notification=payload,
            topic=app_bundle_id,
            priority=NotificationPriority.High
        )

        if result["status"] == "success":
            logger.info(f"Security alert sent to {user_ip}: {message}")
            return True
        else:
            logger.error(f"Failed to send security alert to {user_ip}: {result}")
            return False

    except Exception as e:
        logger.error(f"Error sending security alert to {user_ip}: {str(e)}")
        return False


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


def send_security_alert_to_all_users(message: str, url: str = None, reason: str = None):
    """
    Send security alert push notification to ALL registered users

    Args:
        message: Alert message
        url: Suspicious URL (optional)
        reason: Reason for alert (optional)
    """
    if not device_tokens:
        logger.warning("No device tokens registered")
        return {"sent": 0, "failed": 0}

    results = {"sent": 0, "failed": 0}

    for user_ip, device_info in device_tokens.items():
        device_token = device_info['deviceToken']
        app_bundle_id = device_info.get('app_bundle_id', BUNDLE_ID)

        custom_data = {
            "type": "security_alert_broadcast",
            "timestamp": datetime.utcnow().isoformat(),
            "user_ip": user_ip
        }

        if url:
            custom_data["ip"] = url
        if reason:
            custom_data["reason"] = reason

        try:
            payload = Payload(
                alert=message,
                badge=1,
                sound="default",
                custom=custom_data
            )

            result = send_apns_notification(
                token_hex=device_token,
                notification=payload,
                topic=app_bundle_id,
                priority=NotificationPriority.Immediate
            )

            if result["status"] == "success":
                logger.info(f"Security alert sent to {user_ip}")
                results["sent"] += 1
            else:
                logger.error(f"Failed to send security alert to {user_ip}: {result}")
                results["failed"] += 1

        except Exception as e:
            logger.error(f"Error sending security alert to {user_ip}: {str(e)}")
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

        logger.info(f"Incoming request from IP: {user_ip}, Sender: {sender}")

        urls = URL_REGEX.findall(body)
        if urls:
            result_data = controller.main(urls[0])
            is_suspicious = result_data.get('trust_score', 100) < 50
            reason = result_data.get('reason', 'Message from {sender} was filtered as suspicious.'.format(sender=sender))
        else:
            is_suspicious = False
            reason = "No URL found"

        # Store message
        stored_message = _store_message(user_ip, sender, body, is_suspicious, reason)
        alert_message = f"⚠️ Security Alert: {reason}"
        broadcast_results = send_security_alert_to_all_users(
            message=alert_message,
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
        message = data.get("message", "Hello from Flask!")
        badge = data.get("badge", 1)
        sound = data.get("sound", "default")
        custom_data = data.get("custom_data", {})

        if not device_token:
            return jsonify({"error": "Missing deviceToken"}), 400

        payload = Payload(
            alert=message,
            badge=badge,
            sound=sound,
            custom=custom_data
        )

        result = send_apns_notification(
            token_hex=device_token,
            notification=payload,
            topic=BUNDLE_ID,
            priority=NotificationPriority.Immediate
        )

        if result["status"] == "success":
            return jsonify({"status": "Push sent successfully", "details": result}), 200
        else:
            return jsonify({"error": "Failed to send push", "details": result}), 500

    except Exception as e:
        logger.error(f"Error sending push notification: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route('/save-sender', methods=['POST'])
def save_device_token():
    try:
        data = request.get_json()
        user_ip = data.get('user_ip')
        device_token = data.get('deviceToken')

        if not user_ip or not device_token:
            return jsonify({"error": "Missing user_ip or deviceToken"}), 400

        device_tokens[user_ip] = {
            "deviceToken": device_token,
            "registered_at": datetime.utcnow().isoformat()
        }

        return jsonify({"status": "Device token saved successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.debug = True
    app.run()