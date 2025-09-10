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

from flask import Flask, request, jsonify, send_file, render_template

from apns2.client import APNsClient, NotificationPriority
from apns2.credentials import TokenCredentials
from apns2.payload import Payload

from controller import Controller

# ------------------------------------------------------------------------------
# Flask + Logging
# ------------------------------------------------------------------------------
app = Flask(__name__)

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
            use_sandbox=True,  # True for development/testing; False for production
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
    timeout_seconds: int = 5,
) -> str:
    """
    Creates a new suspicious event, sends silent push to all tokens, and starts
    a watchdog thread that will send fallback notifications if no matches arrive.
    """
    event_id = str(uuid.uuid4())
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
        all_tokens = event["tokens"]
        responded = event["responded"]
        missing = list(all_tokens - responded)

        logger.info(f"[Step 6] No matches for event {event_id}. Fallback to {len(missing)} devices.")
        for t in missing:
            send_user_alert(t, ip=ip, sender=sender, body=body, reason=reason, event_id=event_id, suspicious=event.get("suspicious", False))

    # Cleanup (optional to keep memory small)
    # You could keep it longer if you want to inspect the event via /events.
    # Here we keep it so /events can still show recent ones. You can prune later.


# ------------------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------------------
# Step 1: Register device token on app open
@app.route("/save-sender", methods=["POST"])
@app.route("/save-token", methods=["POST"])  # alias, both do the same
def save_device_token():
    """
    Body: { "deviceToken": "<apns token hex>" }
    """
    try:
        data = request.get_json(force=True, silent=False) or {}
        device_token = data.get("deviceToken")

        if not device_token:
            return jsonify({"error": "Missing deviceToken"}), 400

        device_tokens[device_token] = {
            "deviceToken": device_token,
            "registered_at": datetime.utcnow().isoformat() + "Z",
            # "last_ip": "x.x.x.x",  # set later via /report-ip
            # "last_seen": timestamp
        }
        logger.info(f"[Step 1] Registered device: {device_token[:12]}…; total={len(device_tokens)}")
        return jsonify({"status": "Device token saved", "count": len(device_tokens)}), 200

    except Exception as e:
        logger.exception("save_device_token error")
        return jsonify({"error": str(e)}), 500



@app.route('/message-filter', methods=['POST'])
def message_filter_old():
    try:
        data = request.get_json()

        user_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
        sender = data.get('query', {}).get('sender', 'Unknown')
        body = data.get('query', {}).get('message', {}).get('text', '')
        # Ensure body is a string
        if not isinstance(body, str):
            body = str(body) if body is not None else ''

        logger.info(f"Incoming request from IP: {user_ip}, Sender: {sender}")
        logger.info(f"{data.get('query', {})}")
        tokens = list(device_tokens.keys())
        urls = URL_REGEX.findall(body)
        if urls:
            result_data = controller.main(urls[0])
            is_suspicious = result_data.get('trust_score', 60) < 50
            reason = result_data.get('reason', 'Message from {sender} was filtered as suspicious.'.format(sender=sender))
        else:
            is_suspicious = False
            reason = "No suspicious indicators detected"
            event_id = start_suspicious_event(
                ip=user_ip,
                tokens=tokens,
                sender=sender,
                body=body,
                suspicious=False,
                reason=reason,
                timeout_seconds=5,
            )
            return jsonify({'filter': 'allow', 'reason': "No suspicious indicators detected" + user_ip}), 200


        if not tokens:
            logger.warning("[Step 2] No registered devices to notify.")
            return jsonify({"error": "No registered devices"}), 400
        # Extract URLs for response
        urls = URL_REGEX.findall(body)
        if not urls:
            event_id = start_suspicious_event(
                ip=user_ip,
                tokens=tokens,
                sender=sender,
                body=body,
                suspicious=False,
                reason=reason,
                timeout_seconds=5,
            )
            return jsonify({'filter': 'allow', 'reason': "No suspicious indicators detected" + user_ip}), 200

        url_to_check = urls[0]
        result_data = controller.main(url_to_check)
        trust_score = result_data.get('trust_score', 60)
        classification = 'filter' if trust_score < 50 else 'allow'

        event_id = start_suspicious_event(
            ip=user_ip,
            tokens=tokens,
            sender=sender,
            body=body,
            suspicious=True,
            reason=reason,
            timeout_seconds=5,
        )

        response_payload = {
            'filter': "filter",
            'trust_score': trust_score,
            'ip:': user_ip,
            'reason': result_data.get('reason', 'Suspicious URL detected'),
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

@app.route('/message-filter-android', methods=['POST'])
def message_filter_android():
    try:
        data = request.get_json()

        user_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
        sender = data.get('query', {}).get('sender', 'Unknown')
        body = data.get('query', {}).get('message', {}).get('text', '')
        # Ensure body is a string
        if not isinstance(body, str):
            body = str(body) if body is not None else ''

        logger.info(f"Incoming request from IP: {user_ip}, Sender: {sender}")
        logger.info(f"{data.get('query', {})}")
        tokens = list(device_tokens.keys())
        urls = URL_REGEX.findall(body)
        if urls:
            result_data = controller.main(urls[0])
            is_suspicious = result_data.get('trust_score', 60) < 50
            reason = result_data.get('reason', 'Message from {sender} was filtered as suspicious.'.format(sender=sender))
        else:
            is_suspicious = False
            reason = "No suspicious indicators detected"
            return jsonify({'filter': 'allow', 'reason': "No suspicious indicators detected" + user_ip}), 200


        # Extract URLs for response
        urls = URL_REGEX.findall(body)
        if not urls:
            event_id = start_suspicious_event(
                ip=user_ip,
                tokens=tokens,
                sender=sender,
                body=body,
                suspicious=False,
                reason=reason,
                timeout_seconds=5,
            )
            return jsonify({'filter': 'allow', 'reason': "No suspicious indicators detected" + user_ip}), 200

        url_to_check = urls[0]
        result_data = controller.main(url_to_check)
        trust_score = result_data.get('trust_score', 60)
        classification = 'filter' if trust_score < 50 else 'allow'


        response_payload = {
            'filter': "filter",
            'trust_score': trust_score,
            'ip:': user_ip,
            'reason': result_data.get('reason', 'Suspicious URL detected'),
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


@app.route('/api/check-domain', methods=['POST'])
def check_domain_api():
    try:
        data = request.get_json()
        url = data.get('url')
        if not url:
            return jsonify({'error': 'Missing URL'}), 400
        result = controller.main(url)
        trust_score = result.get("trust_score")

        if trust_score is None:
            trust_score = 60

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
    return jsonify({"count": len(device_tokens), "devices": device_tokens}), 200


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

# ------------------------------------------------------------------------------
# Run
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    # For Azure Container Apps (or containers in general), bind to 0.0.0.0:8080
    app.run(host="0.0.0.0", port=8080, debug=True)
