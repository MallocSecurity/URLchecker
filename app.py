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

from flask import Flask, request, jsonify

from apns2.client import APNsClient, NotificationPriority
from apns2.credentials import TokenCredentials
from apns2.payload import Payload

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
    event_id: Optional[str],
) -> Dict[str, Any]:
    """
    Sends a visible alert. Includes a short message and includes context in custom data.
    """
    title = "⚠️ Security Alert"
    body_text = reason or f"Suspicious activity detected from {ip}"
    if sender:
        body_text += f"\nSender: {sender}"
    if body:
        snippet = (body[:120] + "…") if len(body) > 120 else body
        body_text += f"\nMessage: {snippet}"

    custom = {
        "action": "open_alert",
        "event_id": event_id or "",
        "ip": ip,
        "reason": reason or "",
        "sender": sender or "",
    }

    payload = Payload(
        alert={"title": title, "body": body_text},
        sound="default",
        badge=1,
        custom=custom,
    )

    return send_apns_notification(
        token_hex=device_token,
        notification=payload,
        topic=BUNDLE_ID,
        priority=NotificationPriority.Immediate,
    )

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
        "responded": set(),
        "matched": False,
        "timeout": time.time() + max(timeout_seconds, 1),
        "sender": sender,
        "body": body,
        "reason": reason,
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
            send_user_alert(t, ip=ip, sender=sender, body=body, reason=reason, event_id=event_id)

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

# Step 2: Receive filtered/suspicious message → create event & broadcast silent
@app.route("/message-filter", methods=["POST"])
def message_filter():
    """
    Expected JSON:
    {
      "ip": "46.199.91.178",
      "sender": "Alphamega",
      "body": "Phishy text...",
      "reason": "Potential phishing detected",
      "timeout": 5   # optional seconds to wait before fallback
    }
    """
    try:
        data = request.get_json(force=True, silent=False) or {}

        suspicious_ip = data.get("ip")
        if not suspicious_ip:
            return jsonify({"error": "Missing 'ip'"}), 400

        sender = data.get("sender")
        body = data.get("body")
        reason = data.get("reason", "Suspicious message detected")
        timeout_seconds = int(data.get("timeout", 5))

        tokens = list(device_tokens.keys())
        if not tokens:
            logger.warning("[Step 2] No registered devices to notify.")
            return jsonify({"error": "No registered devices"}), 400

        event_id = start_suspicious_event(
            ip=suspicious_ip,
            tokens=tokens,
            sender=sender,
            body=body,
            reason=reason,
            timeout_seconds=timeout_seconds,
        )
        logger.info(f"[Step 2/3] Created event {event_id} for IP {suspicious_ip}; silent broadcast started.")

        return jsonify({"status": "Silent notifications dispatched", "event_id": event_id}), 200

    except Exception as e:
        logger.exception("message_filter error")
        return jsonify({"error": str(e)}), 500

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
