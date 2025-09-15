# app.py
import sys
import re
import json
import uuid
import time
import threading
import logging
from datetime import datetime
from typing import Optional, Dict, Any
from urllib.parse import quote_plus

from flask import Flask, request, jsonify, send_file, render_template

from apns2.client import APNsClient, NotificationPriority
from apns2.credentials import TokenCredentials
from apns2.payload import Payload

from controller import Controller
import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

# Original Azure connection string
raw_conn = os.getenv("AZURE_POSTGRESQL_CONNECTIONSTRING")

# Parse key=value pairs
params = dict(item.split("=", 1) for item in raw_conn.split() if "=" in item)

# Build SQLAlchemy URL
user = quote_plus(params["user"])
password = quote_plus(params["password"])
host = params["host"]
port = params.get("port", "5432")
dbname = params["dbname"]
sslmode = params.get("sslmode", "require")

SQLALCHEMY_DATABASE_URI = f"postgresql+psycopg2://{user}:{password}@{host}:{port}/{dbname}?sslmode={sslmode}"

app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# ------------------------------------------------------------------------------
# Flask + Logging
# ------------------------------------------------------------------------------


class MessageFeedback(db.Model):
    __tablename__ = "message_feedbacks"

    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.String, db.ForeignKey("suspicious_events.event_id"), nullable=False)
    device_token = db.Column(db.Text, nullable=False)
    feedback = db.Column(db.String, nullable=False)  # "safe" or "suspicious"
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "event_id": self.event_id,
            "device_token": self.device_token,
            "feedback": self.feedback,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }



class Device(db.Model):
    __tablename__ = "devices"
    id = db.Column(db.Integer, primary_key=True)
    device_token = db.Column(db.Text, unique=True, nullable=False)
    registered_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime)
    last_ip = db.Column(db.Text)

class UrlScan(db.Model):
    __tablename__ = "url_scans"
    id = db.Column(db.Integer, primary_key=True)
    device_token = db.Column(db.Text, db.ForeignKey("devices.device_token"))
    url = db.Column(db.Text, nullable=False)
    sender = db.Column(db.Text)
    message_body = db.Column(db.Text)
    ip = db.Column(db.Text)
    trust_score = db.Column(db.Integer)
    suspicious = db.Column(db.Boolean)
    reason = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Event(db.Model):
    __tablename__ = "events"
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.String, nullable=False, unique=True)
    device_token = db.Column(db.Text)
    ip = db.Column(db.Text)
    sender = db.Column(db.Text)
    body = db.Column(db.Text)
    reason = db.Column(db.Text)
    suspicious = db.Column(db.Boolean)
    notified = db.Column(db.Boolean, default=False)
    responded = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class UrlReport(db.Model):
    __tablename__ = "url_reports"
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.Text, nullable=False)
    device_token = db.Column(db.Text)
    report_reason = db.Column(db.Text)
    report_date = db.Column(db.DateTime, default=datetime.utcnow)

class SuspiciousEvent(db.Model):
    __tablename__ = "suspicious_events"
    event_id = db.Column(db.String, primary_key=True)
    ip = db.Column(db.Text)
    sender = db.Column(db.Text)
    body = db.Column(db.Text)
    reason = db.Column(db.Text)
    suspicious = db.Column(db.Boolean)
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime)
    fallback_sent = db.Column(db.Boolean, default=False)
    matched = db.Column(db.Boolean, default=False)
    total_devices_targeted = db.Column(db.Integer)
    alerts_sent_count = db.Column(db.Integer, default=0)
    responded_devices = db.Column(db.JSON, default={})
    response_times = db.Column(db.JSON, default={})


class UserAlert(db.Model):
    __tablename__ = "user_alerts"

    id = db.Column(db.Integer, primary_key=True)
    device_token = db.Column(db.Text, nullable=False)
    event_id = db.Column(db.Text, nullable=False)
    ip = db.Column(db.Text)
    sender = db.Column(db.Text)
    body = db.Column(db.Text)
    reason = db.Column(db.Text)
    suspicious = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "device_token": self.device_token,
            "event_id": self.event_id,
            "ip": self.ip,
            "sender": self.sender,
            "body": self.body,
            "reason": self.reason,
            "suspicious": self.suspicious,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

URL_REGEX = re.compile(r"(https?://[^\s]+)", re.IGNORECASE)

# ------------------------------------------------------------------------------
# APNs Configuration (Token-based)
# ------------------------------------------------------------------------------
APNS_KEY_PATH = "AuthKey_VM3QPGGY8L.p8"  # <-- your .p8 private key
TEAM_ID = "JRXD7XLLMM"                   # <-- your Apple Team ID
KEY_ID = "VM3QPGGY8L"                    # <-- your Key ID for the .p8 key
BUNDLE_ID = "com.malloc.phishingprotect" # <-- your app bundle id

# ------------------------------------------------------------------------------
# In-memory stores
# ------------------------------------------------------------------------------
# Device registry: token -> { deviceToken, registered_at, last_ip?, last_seen? }
device_tokens: Dict[str, dict] = {}
controller = Controller()
# Suspicious events store:
#   event_id -> {
#       "ip": str,
#       "tokens": set[str],
#       "responded": set[str],
#       "matched": bool,
#       "timeout": float(epoch),
#       "sender": Optional[str],
#       "body": Optional[str],
#       "reason": Optional[str]
#   }
suspicious_events: Dict[str, dict] = {}


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



# ------------------------------------------------------------------------------
# APNs helpers
# ------------------------------------------------------------------------------
def send_apns_notification(
    token_hex: str,
    notification: Payload,
    topic: Optional[str] = None,
    priority: NotificationPriority = NotificationPriority.Immediate,
    expiration: Optional[int] = None,
    collapse_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Wrapper to send a synchronous APNs notification and capture a structured result.
    """
    try:

        apns_client = APNsClient(
            credentials=TokenCredentials(
                auth_key_path=APNS_KEY_PATH,
                auth_key_id=KEY_ID,
                team_id=TEAM_ID,
            ),
            use_sandbox=False,  # True for development/testing; False for production
        )


        stream_id = apns_client.send_notification_async(
            token_hex, notification, topic, priority, expiration, collapse_id
        )
        result = apns_client.get_notification_result(stream_id)

        if result == "Success":
            logger.info(f"APNs: delivered to {token_hex[:12]}…")
            return {"status": "success", "message": "Notification delivered"}
        else:
            error_msg = f"APNs error: {result}"
            logger.error(f"APNs: failed to {token_hex[:12]}… -> {error_msg}")
            return {"status": "error", "reason": result, "message": error_msg}

    except Exception as e:
        logger.error(f"APNs exception for {token_hex[:12]}…: {e}")
        return {"status": "error", "reason": "Exception", "message": str(e)}

# ------------------------------------------------------------------------------
# Step 3: Send SILENT notification (content-available) to a single device
# ------------------------------------------------------------------------------
def send_silent_notification(device_token: str, *, event_id: str, ip: str) -> Dict[str, Any]:
    """
    Sends a silent push with content_available=1 and custom payload:
        { action: verify_ip, event_id, ip, timestamp }
    """
    custom = {
        "action": "verify_ip",
        "event_id": event_id,
        "ip": ip,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }

    payload = Payload(
        alert=None,               # NO alert -> silent
        badge=None,
        sound=None,
        content_available=True,   # <= required for background wake
        custom=custom,
    )

    return send_apns_notification(
        token_hex=device_token,
        notification=payload,
        topic=BUNDLE_ID,
        priority=NotificationPriority.Immediate,  # deliver promptly
    )

# ------------------------------------------------------------------------------
# Step 5 & 6: Send USER-FACING alert to a single device
# ------------------------------------------------------------------------------
def send_user_alert(
    device_token: str,
    *,
    ip: str,
    sender: Optional[str],
    body: Optional[str],
    reason: Optional[str],
    suspicious: bool,
    event_id: Optional[str],
) -> Optional[dict[str, Any]]:
    """
    Sends a visible alert. Includes a short message and saves it for later fetching.
    """

    body_text=""
    title = f"{ip}|Message Received"

   # body_text = f"Safe message received from  {sender}"
    if suspicious:
        title = f"{ip}|⚠️Security Alert"
       # body_text = reason or f"Suspicious activity detected from {sender}"

    if body:
        snippet = (body[:120] + "…") if len(body) > 120 else body
        body_text += f"{snippet}"

    custom = {
        "action": "open_alert",
        "event_id": event_id or "",
        "ip": ip,
        "body": body_text or "",
        "reason": reason or "",
        "sender": sender or "",
        "isSuspicious": suspicious
    }


    payload = Payload(
        alert={"title": title, "body":body_text},
        sound="default",
        badge=1,
        custom=custom,
        mutable_content=True
    )

    # Save user-facing alert in-memory for later fetch
    event = suspicious_events.get(event_id)
    if event:
        event.setdefault("user_alerts", {})[device_token] = {
            "title": title,
            "body": body_text,
            "ip": ip,
            "id": event_id,
            "sender": sender,
            "reason": reason,
            "event_id": event_id,
            "suspicious": suspicious,
            "date": datetime.utcnow().isoformat() + "Z",
        }

    if suspicious:
        # Inside send_user_alert, after setting event["user_alerts"]
        try:
            alert = UserAlert(
                device_token=device_token,
                event_id=event_id,
                ip=ip,
                sender=sender,
                body=body_text,
                reason=reason,
                suspicious=suspicious,
                created_at=datetime.utcnow()
            )
            db.session.add(alert)
            # Increment alerts_sent_count in SuspiciousEvent
            if event_id:
                event_db = SuspiciousEvent.query.filter_by(event_id=event_id).first()
                if event_db:
                    event_db.alerts_sent_count = (event_db.alerts_sent_count or 0) + 1

            db.session.commit()
        except Exception as db_exc:
            logger.exception(f"Failed to save user alert for {device_token[:12]}: {db_exc}")

        return send_apns_notification(
            token_hex=device_token,
            notification=payload,
            topic=BUNDLE_ID,
            priority=NotificationPriority.Immediate,
        )
    return None


# ------------------------------------------------------------------------------
# Event Orchestration
# ------------------------------------------------------------------------------
# Step 2: Create event + broadcast silence
def start_suspicious_event(
    *,
    ip: str,
    tokens: list[str],
    sender: Optional[str],
    body: Optional[str],
    reason: Optional[str],
    suspicious: bool,
    timeout_seconds: int = 60,
) -> str:
    """
    Creates a new suspicious event, sends silent push to all tokens, and starts
    a watchdog thread that will send fallback notifications if no matches arrive.
    """
    event_id = str(uuid.uuid4())

    try:
        event_id = str(uuid.uuid4())
        # DB persist
        db_event = SuspiciousEvent(
            event_id=event_id,
            ip=ip,
            sender=sender,
            body=body,
            reason=reason,
            suspicious=suspicious,
            total_devices_targeted=len(tokens),
            responded_devices={},
            alerts_sent_count=0,
            matched=False,
            fallback_sent=False
        )
        db.session.add(db_event)
        db.session.commit()
    except Exception as e:
        logger.exception(f"Failed to SAVE suspicious event: {e}")

    suspicious_events[event_id] = {
        "ip": ip,
        "tokens": set(tokens),
        "responded": set(),  # devices that reported IP
        "fetched": set(),  # devices that already fetched notifications
        "matched": False,
        "timeout": time.time() + max(timeout_seconds, 1),
        "sender": sender,
        "body": body,
        "reason": reason,
        "suspicious":suspicious,
        "user_alerts": {},  # token -> alert payload saved for fetching
    }

    # Broadcast silent to all
    for t in tokens:
        res = send_silent_notification(t, event_id=event_id, ip=ip)
        logger.info(f"[Step 3] Silent -> {t[:12]}… ({res.get('status')})")


    # Watchdog for fallback
    threading.Thread(
        target=_watch_event_and_fallback, args=(event_id,), daemon=True
    ).start()

    return event_id

# Step 6: Fallback after timeout
def _watch_event_and_fallback(event_id: str):
    event = suspicious_events.get(event_id)
    if not event:
        return

    # sleep until timeout
    sleep_for = max(0, event["timeout"] - time.time())
    time.sleep(sleep_for)

    # If not matched, notify unresponsive tokens
    if not event.get("matched"):
        ip = event["ip"]
        sender = event.get("sender")
        body = event.get("body")
        reason = event.get("reason")
        tokens = list(device_tokens.keys())
        responded = event["responded"]

        logger.info(f"[Step 6] No matches for event {event_id}. Fallback to {len(tokens)} devices.")
        message = f"[Step 6] No matches for event {event_id}. Fallback to {len(tokens)} devices. Body: {body} . Reason: {reason} . Responded: {responded} IP: {ip}"
        send_slack_message(message)
      # no matches for event. dont fallback
      # for t in tokens:
      #      send_user_alert(t, ip=ip, sender=sender, body=body, reason=reason, event_id=event_id, suspicious=event.get("suspicious", False))

    # Cleanup (optional to keep memory small)
    # You could keep it longer if you want to inspect the event via /events.
    # Here we keep it so /events can still show recent ones. You can prune later.




def send_slack_message(message, username="Bot", icon_emoji=":robot_face:"):
    """
    Send a message payload to a Slack webhook.

    :param message: The text message to send
    :param username: The display name for the bot
    :param icon_emoji: Emoji icon for the bot
    """
    # Set your Slack webhook URL here
    webhook_url = "https://hooks.slack.com/services/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"

    payload = {
        "text": message,
        "username": username,
        "icon_emoji": icon_emoji
    }

    headers = {"Content-Type": "application/json"}
    response = requests.post(webhook_url, data=json.dumps(payload), headers=headers)

    if response.status_code != 200:
        raise Exception(f"Request to Slack returned an error {response.status_code}, "
                        f"the response is:\n{response.text}")
    return response.text


# Example usage:
# send_slack_message("Hello from Python!")

# ------------------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------------------
# Step 1: Register device token on app open
@app.route("/save-sender", methods=["POST"])
@app.route("/save-token", methods=["POST"])
def save_device_token():
    try:
        data = request.get_json(force=True, silent=False) or {}
        device_token = data.get("deviceToken")

        if not device_token:
            return jsonify({"error": "Missing deviceToken"}), 400

        # ---------- DB PERSISTENCE ----------
        try:
            device = Device.query.filter_by(device_token=device_token).first()
            if device:
                device.last_seen = datetime.utcnow()
            else:
                device = Device(
                    device_token=device_token,
                    registered_at=datetime.utcnow()
                )
                db.session.add(device)
            db.session.commit()
        except Exception as db_exc:
            logger.exception(f"Failed to save device to DB: {db_exc}")
        # -----------------------------------

        # ---------- IN-MEMORY STORE ----------
        device_tokens[device_token] = {
            "deviceToken": device_token,
            "registered_at": datetime.utcnow().isoformat() + "Z",
            # last_ip and last_seen will be updated via /report-ip
        }
        logger.info(f"[Step 1] Registered device: {device_token[:12]}…; total={len(device_tokens)}")
        message = f"[Step 1] Registered device: {device_token[:12]}…; total={len(device_tokens)}"
        send_slack_message(message)
        # -----------------------------------

        return jsonify({"status": "Device token saved", "count": len(device_tokens)}), 200

    except Exception as e:
        logger.exception("save_device_token error")
        return jsonify({"error": str(e)}), 500




@app.route('/message-filter', methods=['POST'])
def message_filter_old_db():
    try:
        data = request.get_json()

        user_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
        sender = data.get('query', {}).get('sender', 'Unknown')
        body = data.get('query', {}).get('message', {}).get('text', '')
        if not isinstance(body, str):
            body = str(body) if body is not None else ''

        logger.info(f"Incoming request from IP: {user_ip}, Sender: {sender}")
        logger.info(f"{data.get('query', {})}")
        tokens = list(device_tokens.keys())
        urls = URL_REGEX.findall(body)

        scanned_results = []
        message_suspicious = False

        # ---------- PROCESS URLS ----------
        for url in urls:
            try:
                # Check if URL is already in DB
                scan = UrlScan.query.filter_by(url=url).order_by(UrlScan.created_at.desc()).first()
                reason = " "
                if scan:
                    result_data = {
                        "trust_score": scan.trust_score,
                        "reason": scan.reason,
                        "age": scan.created_at,
                        "rank": None,
                        "is_url_shortened": False,
                        "hsts_support": None
                    }
                    is_suspicious = scan.suspicious
                else:
                    # Not in DB → scan it
                    result_data = controller.main(url)
                    trust_score = result_data.get('trust_score', 0)
                    is_suspicious = trust_score < 25
                    reason = result_data.get('reason', 'URL in message exhibits patterns typical of phishing, such as recent registration, URL obfuscation, or lack of HTTPS enforcement.') if is_suspicious else "No suspicious indicators detected"
                    if trust_score < 1:
                        reason = " Website Not Active - The  URL could not be reached or is invalid"
                    # Save to DB
                    scan = UrlScan(
                        device_token=tokens[0] if tokens else None,
                        url=url,
                        sender=sender,
                        message_body=body,
                        ip=user_ip,
                        trust_score=trust_score,
                        suspicious=is_suspicious,
                        reason=reason
                    )
                    db.session.add(scan)
                    db.session.commit()

                scanned_results.append({
                    "url": url,
                    "trust_score": result_data.get("trust_score", 0),
                    "suspicious": is_suspicious,
                    "reason": reason
                })

                if is_suspicious:
                    message_suspicious = True
                    message = f" Suspicious URL Detected: {url}"
                    send_slack_message(message)
            except Exception as db_exc:
                logger.exception(f"Failed to process URL {url}: {db_exc}")

        # If no URLs, treat as non-suspicious
        if not urls:
            event_id = start_suspicious_event(
                ip=user_ip,
                tokens=tokens,
                sender=sender,
                body=body,
                suspicious=False,
                reason="No suspicious indicators detected",
                timeout_seconds=60,
            )
            return jsonify({'filter': 'allow', 'reason': "No suspicious indicators detected"}), 200

        # Start suspicious event if any URL is suspicious
        if message_suspicious:
            event_id = start_suspicious_event(
                ip=user_ip,
                tokens=tokens,
                sender=sender,
                body=body,
                suspicious=True,
                reason="Suspicious URL detected",
                timeout_seconds=60,
            )
            return jsonify({
                'filter': "filter",
                'user_ip': user_ip,
                'notification_sent': True,
                'urls': scanned_results
            }), 200

        # All URLs are safe
        return jsonify({'filter': 'allow', 'reason': "No suspicious indicators detected", 'urls': scanned_results}), 200

    except Exception as e:
        return jsonify({'filter': 'allow', 'reason': f'Error: {str(e)}'}), 200


@app.route('/message-filter-android', methods=['POST'])
def message_filter_android():
    try:
        data = request.get_json()

        user_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
        sender = data.get('query', {}).get('sender', 'Unknown')
        body = data.get('query', {}).get('message', {}).get('text', '')
        if not isinstance(body, str):
            body = str(body) if body is not None else ''

        logger.info(f"Incoming request from IP: {user_ip}, Sender: {sender}")
        logger.info(f"{data.get('query', {})}")
        tokens = list(device_tokens.keys())
        urls = URL_REGEX.findall(body)
        reason = " "
        any_suspicious = False
        response_payloads = []

        for url in urls:
            try:
                scan = UrlScan.query.filter_by(url=url).order_by(UrlScan.created_at.desc()).first()

                if scan:
                    result_data = {
                        "trust_score": scan.trust_score,
                        "reason": scan.reason,
                        "age": scan.created_at,
                        "rank": None,
                        "is_url_shortened": False,
                        "hsts_support": None
                    }
                    is_suspicious = scan.suspicious
                else:
                    result_data = controller.main(url)
                    trust_score = result_data.get('trust_score', 0)
                    is_suspicious = trust_score < 25
                    reason = result_data.get('reason', 'Suspicious URL detected') if is_suspicious else "No suspicious indicators detected"
                    if trust_score < 1:
                        reason = " Website Not Active - The  URL could not be reached or is invalid"
                    # Save to DB
                    scan = UrlScan(
                        device_token=tokens[0] if tokens else None,
                        url=url,
                        sender=sender,
                        message_body=body,
                        ip=user_ip,
                        trust_score=trust_score,
                        suspicious=is_suspicious,
                        reason=reason
                    )
                    db.session.add(scan)
                    db.session.commit()

                if is_suspicious:
                    any_suspicious = True

                response_payloads.append({
                    "url": url,
                    "trust_score": result_data.get('trust_score', 0),
                    "reason": reason,
                    "age": result_data.get('age'),
                    "rank": result_data.get('rank'),
                    "is_url_shortened": result_data.get('is_url_shortened'),
                    "hsts_support": result_data.get('hsts_support'),
                    "is_suspicious": is_suspicious
                })

            except Exception as db_exc:
                logger.exception(f"Failed to process URL {url}: {db_exc}")

        if any_suspicious:
            return jsonify({
                "filter": "filter",
                "user_ip": user_ip,
                "urls": response_payloads
            }), 200

        return jsonify({
            "filter": "allow",
            "reason": "No suspicious indicators detected",
            "user_ip": user_ip,
            "urls": response_payloads
        }), 200

    except Exception as e:
        return jsonify({'filter': 'allow', 'reason': f'Error: {str(e)}'}), 200



@app.route('/api/check-domain', methods=['POST'])
def check_domain_api():
    try:
        data = request.get_json()
        url = data.get('url')
        if not url:
            return jsonify({'error': 'Missing URL'}), 400

        # ---------- CHECK DB FIRST ----------
        try:
            scan = UrlScan.query.filter_by(url=url).order_by(UrlScan.created_at.desc()).first()
            if scan:
                result = {
                    'status': 'cached',
                    'trust_score': scan.trust_score or 0,
                    'reason': scan.reason or 'No specific reason provided.',
                    'url': scan.url,
                    'age': scan.created_at.isoformat() if scan.created_at else None,
                    'rank': None,
                    'response_status': None,
                    'is_url_shortened': False,
                    'hsts_support': None,
                    'ssl': None,
                    'whois': None
                }
            else:
                # Not in DB → scan it
                result = controller.main(url)
                trust_score = result.get('trust_score', 0)
                # Save to DB
                reason = result.get('reason', '')
                if trust_score < 1:
                    reason = " Website Not Active - The  URL could not be reached or is invalid"
                scan = UrlScan(
                    device_token=None,
                    url=url,
                    sender=None,
                    message_body=None,
                    ip=None,
                    trust_score=trust_score,
                    suspicious=(trust_score < 25),
                    reason=result.get('reason')
                )
                db.session.add(scan)
                db.session.commit()

                # Ensure required fields
                result['trust_score'] = trust_score
                result['status'] = 'scanned'
        except Exception as db_exc:
            logger.exception(f"Failed to access DB for URL {url}: {db_exc}")
            result = result if 'result' in locals() else {'trust_score': 60, 'status': 'error', 'reason': str(db_exc)}

        # Ensure trust_score is always present
        if result.get('trust_score') is None:
            result['trust_score'] = 0

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
        logger.exception("check_domain_api error")
        return jsonify({'error': str(e)}), 500

# Step 4: Device reports back with its IP (after receiving the silent push)
@app.route("/report-ip", methods=["POST"])
def report_ip():
    """
    Expected JSON:
    {
      "deviceToken": "<token>",
      "ip": "x.x.x.x",
      "event_id": "<event id from silent push>"
    }
    """
    try:
        data = request.get_json(force=True, silent=False) or {}
        token = data.get("deviceToken")
        ip = data.get("ip")
        event_id = data.get("event_id")

        if not token or not ip or not event_id:
            return jsonify({"error": "Missing deviceToken, ip, or event_id"}), 400

        # Update device record
        info = device_tokens.get(token)
        if not info:
            return jsonify({"error": "Unknown deviceToken"}), 404

        info["last_ip"] = ip
        info["last_seen"] = datetime.utcnow().isoformat() + "Z"

        # Update event
        event = suspicious_events.get(event_id)
        if not event:
            return jsonify({"error": "Invalid or expired event_id"}), 400

        event["responded"].add(token)
        logger.info(f"[Step 4] Device {token[:12]}… reported IP {ip} for event {event_id}")

        try:
            # Update DB event
            db_event = SuspiciousEvent.query.filter_by(event_id=event_id).first()
            if not db_event:
                logger.warning(f"Unknown event_id {event_id}")
                return False

            responded = db_event.responded_devices or {}
            responded[token] = datetime.utcnow().isoformat() + "Z"
            db_event.responded_devices = responded

            # Match check
            if ip == db_event.ip and not db_event.matched:
                db_event.matched = True
                db_event.end_time = datetime.utcnow()

                if ip == db_event.ip and not getattr(db_event, "matched", False):
                    db_event.matched = True
                    db_event.end_time = datetime.utcnow()
                    logger.info(f"[Step 5] MATCH persisted for event {event_id} with device {token[:12]}…")

                db.session.commit()
        except Exception as e:
            logger.exception(f"Failed to SAVE  event {event_id}: {e}")

        # Step 5: If match, send user-facing push to THIS device
        if ip == event["ip"]:
            if not event.get("matched"):
                event["matched"] = True
                logger.info(f"[Step 5] MATCH for event {event_id}. Alerting {token[:12]}…")
            # Send alert (even if already matched previously, you may still alert this device)
            send_user_alert(
                token,
                ip=event["ip"],
                sender=event.get("sender"),
                body=event.get("body"),
                reason=event.get("reason"),
                suspicious= event.get("suspicious"),
                event_id=event_id,
            )

        return jsonify({"status": "ok"}), 200

    except Exception as e:
        logger.exception("report_ip error")
        return jsonify({"error": str(e)}), 500

# Utility: list devices
@app.route("/registered-devices", methods=["GET"])
def get_registered_devices():
    try:
        # Get limit from query params, default to 20
        limit = int(request.args.get("limit", 20))

        # Query the database
        devices = Device.query.order_by(Device.registered_at.desc()).limit(limit).all()

        # Convert to list of dicts
        devices_list = [
            {
                "id": d.id,
                "device_token": d.device_token,
                "registered_at": d.registered_at.isoformat() if d.registered_at else None,
                "last_seen": d.last_seen.isoformat() if d.last_seen else None,
                "last_ip": d.last_ip,
            }
            for d in devices
        ]

        return jsonify({
            "count": len(devices_list),
            "devices": devices_list
        }), 200

    except Exception as e:
        logger.exception("get_registered_devices error")
        return jsonify({"error": str(e)}), 500

@app.route("/clear-urls", methods=["POST"])
def clear_urls():
    try:
        deleted_count = UrlScan.query.delete()
        db.session.commit()
        logger.info(f"Cleared UrlScan table, deleted {deleted_count} rows.")
        return jsonify({"status": "success", "deleted": deleted_count}), 200
    except Exception as e:
        logger.exception("Failed to clear UrlScan table")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/scanned-urls", methods=["GET"])
def view_scanned_urls():
    try:
        # Get limit from query params, default to 20
        limit = int(request.args.get("limit", 20))

        scans = UrlScan.query.order_by(UrlScan.created_at.desc()).limit(limit).all()
        results = []
        for scan in scans:
            results.append({
                "id": scan.id,
                "url": scan.url,
                "trust_score": scan.trust_score,
                "suspicious": scan.suspicious,
                "reason": scan.reason,
                "sender": scan.sender,
                "device_token": scan.device_token,
                "message_body": scan.message_body,
                "ip": scan.ip,
                "created_at": scan.created_at.isoformat()
            })
        return jsonify(results), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/get-missed-notifications", methods=["POST"])
def get_missed_notifications():
    """
    Expected JSON:
    {
        "deviceToken": "<token>"
    }

    Returns all events that were sent to this device but not yet responded/fetched.
    Removes the device token from `responded` after sending so it's not sent again.
    """
    try:
        data = request.get_json(force=True, silent=False) or {}
        token = data.get("deviceToken")

        if not token:
            return jsonify({"error": "Missing deviceToken"}), 400

        if token not in device_tokens:
            return jsonify({"error": "Unknown deviceToken"}), 404

        missed_messages = []

        # Gather events targeted to this device and not yet responded
        for event_id, event in suspicious_events.items():
            responded_set = event.get("responded", set())
            if token in responded_set:
                # Build the SMS payload
                sms = {
                    "id": event_id,
                    "sender": event.get("sender") or "",
                    "body": event.get("body") or "",
                    "ip": event["ip"],
                    "date": datetime.utcnow().isoformat() + "Z",
                    "isSuspicious":  event.get("suspicious"),
                    "reason": event.get("reason") or "",
                    "category": "security_alert",
                }
                missed_messages.append(sms)

                # ✅ Remove token from responded to mark it "sent"
                responded_set.discard(token)
                event["responded"] = responded_set

        logger.info(f"[Fetch Missed] {len(missed_messages)} messages for {token[:12]}…")
        return jsonify(missed_messages), 200

    except Exception as e:
        logger.exception("get_missed_notifications error")
        return jsonify({"error": str(e)}), 500

@app.route("/acknowledge-notification", methods=["POST"])
def acknowledge_notification():
    """
    Device reports that it received a message for a specific event_id.
    Body:
    {
        "deviceToken": "<token>",
        "event_id": "<event id>"
    }
    """
    try:
        data = request.get_json(force=True, silent=False) or {}
        token = data.get("deviceToken")
        event_id = data.get("event_id")

        if not token or not event_id:
            return jsonify({"error": "Missing deviceToken or event_id"}), 400

        if event_id not in suspicious_events:
            return jsonify({"error": "Invalid event_id"}), 404

        event = suspicious_events[event_id]
        responded_set = event.get("responded", set())

        if token in responded_set:
            responded_set.remove(token)
            event["responded"] = responded_set
            logger.info(f"Device {token[:12]} acknowledged event {event_id}")
            return jsonify({"status": "acknowledged"}), 200
        else:
            return jsonify({"status": "already acknowledged"}), 200

    except Exception as e:
        logger.exception("acknowledge_notification error")
        return jsonify({"error": str(e)}), 500


# Utility: inspect events (current in-memory snapshot)
@app.route("/events", methods=["GET"])
def get_events():
    # present a simplified snapshot
    out = {}
    for ev_id, ev in suspicious_events.items():
        out[ev_id] = {
            "ip": ev["ip"],
            "sender": ev.get("sender"),
            "reason": ev.get("reason"),
            "tokens_total": len(ev["tokens"]),
            "responded": list(ev["responded"]),
            "matched": ev["matched"],
            "timeout_at": ev["timeout"],
        }
    return jsonify(out), 200

def load_device_tokens_from_db():
    """
    Load all devices from the DB into the in-memory device_tokens dictionary.
    """
    global device_tokens
    try:
        all_devices = Device.query.all()
        device_tokens = {
            d.device_token: {
                "deviceToken": d.device_token,
                "registered_at": d.registered_at.isoformat() if d.registered_at else None,
                "last_seen": d.last_seen.isoformat() if d.last_seen else None,
                "last_ip": d.last_ip
            }
            for d in all_devices
        }
        logger.info(f"[load_device_tokens] Loaded {len(device_tokens)} device tokens from DB.")
    except Exception as e:
        logger.exception(f"[load_device_tokens] Failed: {e}")


@app.route("/load", methods=["POST"])
def reload_device_tokens():
    try:
        load_device_tokens_from_db()
        return jsonify({
            "status": "success",
            "count": len(device_tokens),
            "devices": list(device_tokens.keys())
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500



@app.route("/report-sms-feedback", methods=["POST"])
def report_sms_feedback():
    """
    Expected JSON from Android:
    {
        "deviceToken": "<device token>",
        "event_id": "<sms id>",
        "feedback": "safe" | "suspicious"
    }
    """
    try:
        data = request.get_json(force=True) or {}
        device_token = data.get("deviceToken")
        event_id = data.get("event_id")
        feedback = data.get("feedback")

        if not device_token or not event_id or not feedback:
            return jsonify({"error": "Missing fields"}), 400

        # Validate device
        device = Device.query.filter_by(device_token=device_token).first()
        if not device:
            return jsonify({"error": "Unknown deviceToken"}), 404

        # Validate event
        event = SuspiciousEvent.query.filter_by(event_id=event_id).first()
        if not event:
            return jsonify({"error": "Unknown event_id"}), 404

        # Save feedback
        fb = MessageFeedback(
            event_id=event_id,
            device_token=device_token,
            feedback=feedback
        )
        db.session.add(fb)

        # Update event.response_times
        response_times = event.response_times or {}
        response_times[device_token] = datetime.utcnow().isoformat() + "Z"
        event.response_times = response_times

        db.session.commit()

        return jsonify({"status": "success"}), 200

    except Exception as e:
        logger.exception("report_sms_feedback error")
        return jsonify({"error": str(e)}), 500


# ------------------------------------------------------------------------------
# Run
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    # For Azure Container Apps (or containers in general), bind to 0.0.0.0:8080
    with app.app_context():
        load_device_tokens_from_db()
    app.run(host="0.0.0.0", port=8080, debug=True)
