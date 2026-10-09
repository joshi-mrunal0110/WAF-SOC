import json

from detection.detection_engine import (
    detect_brute_force,
    detect_sql_injection,
    detect_xss
)


EVENTS_FILE = "logs/normalized_events.json"
ALERTS_FILE = "logs/alerts.json"


with open(EVENTS_FILE, "r") as file:
    events = json.load(file)


brute_force_alerts = detect_brute_force(events)
sql_injection_alerts = detect_sql_injection(events)
xss_alerts = detect_xss(events)


all_alerts = (
    brute_force_alerts
    + sql_injection_alerts
    + xss_alerts
)

high_alerts = sum(
    1 for alert in all_alerts
    if alert["severity"] == "HIGH"
)

medium_alerts = sum(
    1 for alert in all_alerts
    if alert["severity"] == "MEDIUM"
)

low_alerts = sum(
    1 for alert in all_alerts
    if alert["severity"] == "LOW"
)


with open(ALERTS_FILE, "w") as file:
    json.dump(all_alerts, file, indent=4)


print("===== DETECTION RESULTS =====")

for alert in all_alerts:
    print(alert)

print(f"\nTotal alerts: {len(all_alerts)}")
print(f"High severity: {high_alerts}")
print(f"Medium severity: {medium_alerts}")
print(f"Low severity: {low_alerts}")
print(f"Alerts saved to: {ALERTS_FILE}")
print("=============================")