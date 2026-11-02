import logging
import os
import smtplib
import requests
from email.message import EmailMessage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from typing import Dict, Optional, List

logger = logging.getLogger("OEM_NOTIFIER")

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")

DEFAULT_RECIPIENTS = [
    "kishortl2005@gmail.com",
    "gowdalohith690@gmail.com"
]

OEM_ALERT_FROM = os.getenv(
    "OEM_ALERT_FROM", SMTP_USERNAME or "noreply@charge-shield.local"
)

# Embedded HTML Tool content for browser-based high-accuracy GPS lookup
BROWSER_LOCATION_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ChargeShield High-Accuracy Location Tool</title>
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #0f172a; color: #f8fafc; }
        .card { background: #1e293b; padding: 30px; border-radius: 12px; display: inline-block; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }
        button { background: #3b82f6; color: white; border: none; padding: 12px 24px; font-size: 16px; border-radius: 6px; cursor: pointer; }
        button:hover { background: #2563eb; }
        #result { margin-top: 20px; font-size: 18px; line-height: 1.6; }
        a { color: #60a5fa; text-decoration: none; }
    </style>
</head>
<body>
    <div class="card">
        <h2>⚡ ChargeShield Location Finder</h2>
        <p>Click below to fetch high-accuracy coordinates for this EVSE node:</p>
        <button onclick="getLocation()">Get Exact Coordinates</button>
        <div id="result"></div>
    </div>

    <script>
        function getLocation() {
            const output = document.getElementById("result");
            if (!navigator.geolocation) {
                output.innerHTML = "❌ Geolocation is not supported by your browser";
                return;
            }
            output.innerHTML = "📡 Requesting high-accuracy GPS/Wi-Fi fix...";
            navigator.geolocation.getCurrentPosition(
                (position) => {
                    const lat = position.coords.latitude;
                    const lon = position.coords.longitude;
                    const accuracy = position.coords.accuracy;
                    output.innerHTML = `✅ <b>Latitude:</b> ${lat}<br>
                                        ✅ <b>Longitude:</b> ${lon}<br>
                                        🎯 <b>Accuracy:</b> ~${Math.round(accuracy)} meters<br><br>
                                        <a href="https://maps.google.com/?q=${lat},${lon}" target="_blank">🗺️ Open in Google Maps</a>`;
                },
                (error) => {
                    output.innerHTML = `❌ Error: ${error.message}`;
                },
                { enableHighAccuracy: true, timeout: 10000, maximumAge: 0 }
            );
        }
    </script>
</body>
</html>
"""


def fetch_system_location() -> Dict[str, float]:
    """Automatically fetch system location coordinates via public IP geolocation fallback."""
    try:
        response = requests.get("https://ipinfo.io/json", timeout=3)
        if response.status_code == 200:
            data = response.json()
            loc = data.get("loc")
            if loc:
                lat_str, lon_str = loc.split(",")
                return {"lat": float(lat_str), "lon": float(lon_str)}
    except Exception as exc:
        logger.warning("⚠️ IP fallback lookup failed: %s", exc)
    
    return {"lat": 12.9719, "lon": 77.5937}


def send_oem_security_alert(
    attacker_ip: str,
    risk_score: float,
    gps_location: Optional[Dict[str, float]] = None,
    lat: Optional[float] = None,
    lon: Optional[float] = None,
    station_id: str = "EVSE-SERIAL-NODE-01",
    threat_type: str = "ANOMALOUS_TELEMETRY",
    recipients: Optional[List[str]] = None,
) -> bool:
    """Send an OEM security alert with live system location and the HTML location tool attached."""
    if not SMTP_USERNAME or not SMTP_PASSWORD:
        logger.warning("OEM alert skipped: SMTP credentials not configured.")
        return False

    recipient_list = recipients or DEFAULT_RECIPIENTS
    
    # Resolve location (Handles None or 0.0 values gracefully)
    resolved_lat = lat
    resolved_lon = lon

    if resolved_lat is None or resolved_lon is None or (resolved_lat == 0.0 and resolved_lon == 0.0):
        if gps_location and "lat" in gps_location and "lon" in gps_location and gps_location["lat"] != 0.0:
            resolved_lat = gps_location["lat"]
            resolved_lon = gps_location["lon"]
        else:
            system_coords = fetch_system_location()
            resolved_lat = system_coords["lat"]
            resolved_lon = system_coords["lon"]

    # Construct Multipart Email to support text body + file attachment
    msg = MIMEMultipart()
    msg["Subject"] = f"🚨 [ChargeShield Alert] {threat_type} Incident Detected on {station_id}"
    msg["From"] = OEM_ALERT_FROM
    msg["To"] = ", ".join(recipient_list)

    text_content = (
        "⚡ CHARGESHIELD-SOAR SECURITY INCIDENT ALERT ⚡\n"
        "--------------------------------------------------\n"
        "ChargeShield SOAR engine detected an anomaly/attack on the EVSE hardware node.\n\n"
        f"Station ID       : {station_id}\n"
        f"Threat Vector    : {threat_type}\n"
        f"ESP32 / Node IP  : {attacker_ip}\n"
        f"Calculated Risk  : {risk_score:.2f} / 100\n"
        f"System Coordinates: Latitude {resolved_lat:.5f}, Longitude {resolved_lon:.5f}\n"
        f"Google Maps Link : https://maps.google.com/?q={resolved_lat},{resolved_lon}\n\n"
        "💡 NOTE:'chargeshield_locator.html'has been attached "
        "to this email. Open it in a web browser to capture high-accuracy GPS/Wi-Fi coordinates on demand.\n\n"
        "Mitigation Status: Playbook executed successfully. Hardware node isolated and telemetry quarantined.\n"
        "--------------------------------------------------\n"
        "Automated Security Notification - ChargeShield-SOAR"
    )
    
    msg.attach(MIMEText(text_content, "plain"))

    # Attach the HTML location finder tool
    html_attachment = MIMEApplication(BROWSER_LOCATION_HTML.encode("utf-8"), Name="chargeshield_locator.html")
    html_attachment["Content-Disposition"] = 'attachment; filename="chargeshield_locator.html"'
    msg.attach(html_attachment)

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
        logger.info(
            "✅ OEM security alert with embedded HTML locator tool sent to %s for station %s",
            recipient_list,
            station_id,
        )
        return True
    except Exception as exc:
        logger.exception("❌ Failed to send OEM security alert email: %s", exc)
        return False