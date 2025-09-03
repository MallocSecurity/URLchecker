import sys
import logging
import uuid
import time
import threading
import sqlite3
from datetime import datetime
import firebase_admin
from firebase_admin import credentials, messaging
from flask import Flask, request, render_template, jsonify, send_file

from controller import Controller

# ----------------------------------------------------------------------------
# Setup
# ----------------------------------------------------------------------------
app = Flask(__name__)

cred = credentials.Certificate("malloc-sms-phishing-protect-firebase-adminsdk-fbsvc-841974cf1d.json")
firebase_admin.initialize_app(cred)

logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

device_tokens = {}  # token -> { registered_at }
suspicious_events = {}  # in-memory event tracker

DB_FILE = "events.db"

user_message_store = {}

controller = Controller()
# ----------------------------------------------------------------------------
# SQLite Helpers
# ----------------------------------------------------------------------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY,
                    ip TEXT,
                    sender TEXT,
                    body TEXT,
                    reason TEXT,
                    created_at TEXT,
                    matched INTEGER DEFAULT 0
                )""")
    c.execute("""CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT,
                    device_token TEXT,
                    ip TEXT,
                    reported_at TEXT
                )""")
    c.execute("""CREATE TABLE IF NOT EXISTS notifications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT,
                    device_token TEXT,
                    type TEXT,
                    status TEXT,
                    created_at TEXT
                )""")
    conn.commit()
    conn.close()


def log_event(event_id, ip, sender, body, reason):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO events (id, ip, sender, body, reason, created_at) VALUES (?,?,?,?,?,?)",
              (event_id, ip, sender, body, reason, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()


def log_report(event_id, token, ip):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO reports (event_id, device_token, ip, reported_at) VALUES (?,?,?,?)",
              (event_id, token, ip, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()


def log_notification(event_id, token, notif_type, status):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO notifications (event_id, device_token, type, status, created_at) VALUES (?,?,?,?,?)",
              (event_id, token, notif_type, status, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()



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



# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
def send_silent_notification(token: str, ip: str, event_id: str):
    """Step 2 → Silent push"""
    try:
        message = messaging.Message(
            token=token,
            data={
                "action": "verify_ip",
                "ip": str(ip),
                "event_id": str(event_id)
            },
            android=messaging.AndroidConfig(priority="high"),
            apns=messaging.APNSConfig(
                payload=messaging.APNSPayload(
                    aps=messaging.Aps(content_available=True)
                )
            )
        )
        response = messaging.send(message)
        logger.info(f"[Step 2] Silent push sent to {token[:10]}... for event {event_id}")
        log_notification(event_id, token, "silent", "success")
        return {"status": "success", "message_id": response}
    except Exception as e:
        logger.error(f"[Step 2] Silent push failed: {e}")
        log_notification(event_id, token, "silent", "error")
        return {"status": "error", "reason": str(e)}


def send_user_alert(token: str, ip: str, sender: str = None, body: str = None, reason: str = None, event_id: str = None):
    """Step 5a / 5b → User-facing push"""
    try:
        title = "⚠️ Security Alert"
        notification_body = reason or f"Suspicious activity detected from {ip}"

        if sender:
            notification_body += f"\nSender: {sender}"
        if body:
            snippet = (body[:100] + "...") if len(body) > 100 else body
            notification_body += f"\nMessage: {snippet}"

        message = messaging.Message(
            token=token,
            notification=messaging.Notification(
                title=title,
                body=notification_body
            ),
            data={"ip": str(ip)}
        )
        response = messaging.send(message)
        logger.info(f"[Step 5] User alert sent to {token[:10]}... for IP {ip}")
        log_notification(event_id, token, "alert", "success")
        return {"status": "success", "message_id": response}
    except Exception as e:
        logger.error(f"[Step 5] User alert failed: {e}")
        log_notification(event_id, token, "alert", "error")
        return {"status": "error", "reason": str(e)}


def watch_event_and_fallback(event_id):
    """Step 6 → If no match, fallback alert"""
    event = suspicious_events.get(event_id)
    if not event:
        return

    wait = max(0, event["timeout"] - datetime.utcnow().timestamp())
    time.sleep(wait)

    ip = event["ip"]
    tokens = set(event["tokens"])
    responded = event["responded"]
    missing = tokens - responded

    if not event.get("matched"):
        logger.info(f"[Step 6] No match for IP {ip}, sending fallback notifications")
        for t in missing:
            send_user_alert(t, ip, event.get("sender"), event.get("body"), event.get("reason"), event_id)

    suspicious_events.pop(event_id, None)


def start_suspicious_event(ip, tokens, sender, body, reason, timeout=5):
    """Step 2 → Create event and push silent notifications"""
    event_id = str(uuid.uuid4())
    suspicious_events[event_id] = {
        "ip": ip,
        "tokens": tokens,
        "responded": set(),
        "timeout": datetime.utcnow().timestamp() + timeout,
        "sender": sender,
        "body": body,
        "reason": reason,
        "matched": False
    }

    log_event(event_id, ip, sender, body, reason)

    for t in tokens:
        send_silent_notification(t, ip, event_id)

    threading.Thread(target=watch_event_and_fallback, args=(event_id,), daemon=True).start()
    return event_id


# ----------------------------------------------------------------------------
# Routes
# ----------------------------------------------------------------------------
@app.route("/save-token", methods=["POST"])
def save_device_token():
    """Step 1 → Register device"""
    data = request.get_json()
    device_token = data.get("deviceToken")
    if not device_token:
        return jsonify({"error": "Missing deviceToken"}), 400

    device_tokens[device_token] = {
        "registered_at": datetime.utcnow().isoformat()
    }
    return jsonify({"status": "Token saved", "count": len(device_tokens)})


@app.route("/filter-message", methods=["POST"])
def filter_message():
    """Step 2 → Suspicious message filtering starts"""
    data = request.get_json()
    suspicious_ip = data["ip"]
    sender = data.get("sender")
    body = data.get("body")
    reason = data.get("reason", "Suspicious message detected")
    tokens = list(device_tokens.keys())

    if not tokens:
        return jsonify({"error": "No registered devices"}), 400

    event_id = start_suspicious_event(suspicious_ip, tokens, sender, body, reason)
    return jsonify({"status": "Silent notifications dispatched", "event_id": event_id})


@app.route("/report-ip", methods=["POST"])
def report_ip():
    """Step 4 → Devices respond with IP"""
    data = request.get_json()
    token = data["deviceToken"]
    ip = data["ip"]
    event_id = data.get("event_id")

    event = suspicious_events.get(event_id)
    if not event:
        return jsonify({"error": "Invalid or expired event"}), 400

    event["responded"].add(token)
    log_report(event_id, token, ip)

    if ip == event["ip"]:
        event["matched"] = True
        send_user_alert(token, ip, event.get("sender"), event.get("body"), event.get("reason"), event_id)

    return jsonify({"status": "Reported successfully"})


@app.route("/registered-devices", methods=["GET"])
def get_registered_devices():
    return jsonify({
        "count": len(device_tokens),
        "devices": device_tokens
    })


@app.route("/events", methods=["GET"])
def get_events():
    """Retrieve history of suspicious events"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT * FROM events ORDER BY created_at DESC")
    rows = c.fetchall()
    conn.close()
    return jsonify(rows)


# ----------------------------------------------------------------------------
# Run
# ----------------------------------------------------------------------------




if __name__ == '__main__':
    app.debug = True
    init_db()
    app.run()